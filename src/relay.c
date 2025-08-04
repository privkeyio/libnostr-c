#include "nostr.h"
#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#ifdef NOSTR_FEATURE_THREADING
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif
#endif
#include <time.h>
#include <cjson/cJSON.h>

typedef struct subscription {
    char* id;
    nostr_event_callback callback;
    void* user_data;
    struct subscription* next;
} subscription_t;

typedef struct {
    char* data;
    size_t len;
    struct lws_context* context;
    struct lws* wsi;
    nostr_relay_callback state_callback;
    void* user_data;
    nostr_message_callback message_callback;
    void* message_user_data;
#ifdef NOSTR_FEATURE_THREADING
#ifdef _WIN32
    CRITICAL_SECTION queue_mutex;
#else
    pthread_mutex_t queue_mutex;
#endif
#endif
    bool reconnect_enabled;
    int reconnect_interval;
    time_t last_connect_attempt;
    subscription_t* subscriptions;
    char* receive_buffer;
    size_t buffer_size;
    size_t buffer_pos;
} relay_context;

static int callback_nostr_relay(struct lws* wsi, enum lws_callback_reasons reason,
                               void* user, void* in, size_t len);

#ifdef NOSTR_FEATURE_THREADING
static int init_queue_mutex(relay_context* ctx) {
#ifdef _WIN32
    __try {
        InitializeCriticalSection(&ctx->queue_mutex);
        return 0;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
#else
    return pthread_mutex_init(&ctx->queue_mutex, NULL);
#endif
}

static void destroy_queue_mutex(relay_context* ctx) {
#ifdef _WIN32
    DeleteCriticalSection(&ctx->queue_mutex);
#else
    pthread_mutex_destroy(&ctx->queue_mutex);
#endif
}

static void lock_queue_mutex(relay_context* ctx) {
#ifdef _WIN32
    EnterCriticalSection(&ctx->queue_mutex);
#else
    pthread_mutex_lock(&ctx->queue_mutex);
#endif
}

static void unlock_queue_mutex(relay_context* ctx) {
#ifdef _WIN32
    LeaveCriticalSection(&ctx->queue_mutex);
#else
    pthread_mutex_unlock(&ctx->queue_mutex);
#endif
}
#else
static int init_queue_mutex(relay_context* ctx) { (void)ctx; return 0; }
static void destroy_queue_mutex(relay_context* ctx) { (void)ctx; }
static void lock_queue_mutex(relay_context* ctx) { (void)ctx; }
static void unlock_queue_mutex(relay_context* ctx) { (void)ctx; }
#endif

static struct lws_protocols protocols[] = {
    {
        "nostr-protocol",
        callback_nostr_relay,
        sizeof(relay_context),
        65536,
    },
    { NULL, NULL, 0, 0 }
};

nostr_error_t nostr_relay_create(nostr_relay** relay, const char* url) {
    if (!relay || !url) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    *relay = calloc(1, sizeof(nostr_relay));
    if (!*relay) {
        return NOSTR_ERR_MEMORY;
    }

    (*relay)->url = strdup(url);
    if (!(*relay)->url) {
        free(*relay);
        return NOSTR_ERR_MEMORY;
    }

    (*relay)->state = NOSTR_RELAY_DISCONNECTED;
    (*relay)->ws_handle = NULL;
    (*relay)->user_data = NULL;
    (*relay)->message_callback = NULL;
    (*relay)->message_user_data = NULL;

    return NOSTR_OK;
}

void nostr_relay_destroy(nostr_relay* relay) {
    if (!relay) return;

    if (relay->state == NOSTR_RELAY_CONNECTED || relay->state == NOSTR_RELAY_CONNECTING) {
        nostr_relay_disconnect(relay);
    }

    free(relay->url);
    free(relay);
}

nostr_error_t nostr_relay_connect(nostr_relay* relay, nostr_relay_callback callback, void* user_data) {
    if (!relay || !callback) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (relay->state == NOSTR_RELAY_CONNECTED || relay->state == NOSTR_RELAY_CONNECTING) {
        return NOSTR_ERR_CONNECTION;
    }

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

    struct lws_context* context = lws_create_context(&info);
    if (!context) {
        return NOSTR_ERR_CONNECTION;
    }

    struct lws_client_connect_info ccinfo;
    memset(&ccinfo, 0, sizeof(ccinfo));
    ccinfo.context = context;
    ccinfo.port = 443;
    ccinfo.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
    
    char* url_copy = strdup(relay->url);
    if (strncmp(url_copy, "wss://", 6) == 0) {
        ccinfo.address = url_copy + 6;
        ccinfo.ssl_connection = LCCSCF_USE_SSL;
    } else if (strncmp(url_copy, "ws://", 5) == 0) {
        ccinfo.address = url_copy + 5;
        ccinfo.port = 80;
        ccinfo.ssl_connection = 0;
    } else {
        free(url_copy);
        lws_context_destroy(context);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    char* path = strchr(ccinfo.address, '/');
    if (path) {
        *path = '\0';
        ccinfo.path = path + 1;
    } else {
        ccinfo.path = "/";
    }
    
    ccinfo.host = ccinfo.address;
    ccinfo.origin = ccinfo.address;
    ccinfo.protocol = protocols[0].name;

    relay_context* ctx = calloc(1, sizeof(relay_context));
    if (!ctx) {
        free(url_copy);
        lws_context_destroy(context);
        return NOSTR_ERR_MEMORY;
    }
    
    ctx->context = context;
    ctx->state_callback = callback;
    ctx->user_data = user_data;
    ctx->reconnect_enabled = true;
    ctx->reconnect_interval = 5;
    ctx->last_connect_attempt = time(NULL);
    ctx->subscriptions = NULL;
    ctx->receive_buffer = NULL;
    ctx->buffer_size = 0;
    ctx->buffer_pos = 0;
    ctx->message_callback = relay->message_callback;
    ctx->message_user_data = relay->message_user_data;
    if (init_queue_mutex(ctx) != 0) {
        free(url_copy);
        free(ctx);
        lws_context_destroy(context);
        relay->state = NOSTR_RELAY_ERROR;
        return NOSTR_ERR_MEMORY;
    }
    
    relay->ws_handle = ctx;
    relay->state = NOSTR_RELAY_CONNECTING;
    
    struct lws* wsi = lws_client_connect_via_info(&ccinfo);
    if (!wsi) {
        free(url_copy);
        free(ctx);
        lws_context_destroy(context);
        relay->state = NOSTR_RELAY_ERROR;
        return NOSTR_ERR_CONNECTION;
    }
    
    ctx->wsi = wsi;
    lws_set_opaque_user_data(wsi, relay);
    free(url_copy);
    
    if (callback) {
        callback(relay, NOSTR_RELAY_CONNECTING, user_data);
    }

    return NOSTR_OK;
}

nostr_error_t nostr_relay_disconnect(nostr_relay* relay) {
    if (!relay || !relay->ws_handle) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    relay_context* ctx = (relay_context*)relay->ws_handle;
    ctx->reconnect_enabled = false;
    
    if (ctx->wsi) {
        lws_close_reason(ctx->wsi, LWS_CLOSE_STATUS_NORMAL, NULL, 0);
    }
    
    if (ctx->context) {
        lws_context_destroy(ctx->context);
    }
    
    destroy_queue_mutex(ctx);
    
    while (ctx->subscriptions) {
        subscription_t* sub = ctx->subscriptions;
        ctx->subscriptions = sub->next;
        free(sub->id);
        free(sub);
    }
    
    free(ctx->data);
    free(ctx->receive_buffer);
    free(ctx);
    
    relay->ws_handle = NULL;
    relay->state = NOSTR_RELAY_DISCONNECTED;

    return NOSTR_OK;
}

nostr_error_t nostr_relay_send_event(nostr_relay* relay, const nostr_event* event) {
    if (!relay || !event || relay->state != NOSTR_RELAY_CONNECTED) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    char* json;
    nostr_error_t err = nostr_event_to_json(event, &json);
    if (err != NOSTR_OK) {
        return err;
    }

    relay_context* ctx = (relay_context*)relay->ws_handle;
    if (!ctx || !ctx->wsi) {
        free(json);
        return NOSTR_ERR_CONNECTION;
    }

    char* msg = malloc(strlen(json) + 20);
    if (!msg) {
        free(json);
        return NOSTR_ERR_MEMORY;
    }
    
    sprintf(msg, "[\"EVENT\",%s]", json);
    free(json);
    
    size_t msg_len = strlen(msg);
    unsigned char* buf = malloc(LWS_PRE + msg_len);
    if (!buf) {
        free(msg);
        return NOSTR_ERR_MEMORY;
    }
    
    memcpy(&buf[LWS_PRE], msg, msg_len);
    
    int result = lws_write(ctx->wsi, &buf[LWS_PRE], msg_len, LWS_WRITE_TEXT);
    
    free(msg);
    free(buf);
    
    return (result < 0) ? NOSTR_ERR_CONNECTION : NOSTR_OK;
}


nostr_error_t nostr_subscribe(nostr_relay* relay, const char* subscription_id, 
                             const char* filters_json, nostr_event_callback callback, void* user_data) {
    if (!relay || !subscription_id || !filters_json || relay->state != NOSTR_RELAY_CONNECTED) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    relay_context* ctx = (relay_context*)relay->ws_handle;
    if (!ctx || !ctx->wsi) {
        return NOSTR_ERR_CONNECTION;
    }

    subscription_t* sub = malloc(sizeof(subscription_t));
    if (!sub) {
        return NOSTR_ERR_MEMORY;
    }
    
    sub->id = strdup(subscription_id);
    sub->callback = callback;
    sub->user_data = user_data;
    sub->next = ctx->subscriptions;
    ctx->subscriptions = sub;

    char* msg = malloc(strlen(subscription_id) + strlen(filters_json) + 20);
    if (!msg) {
        return NOSTR_ERR_MEMORY;
    }
    
    sprintf(msg, "[\"REQ\",\"%s\",%s]", subscription_id, filters_json);
    
    size_t msg_len = strlen(msg);
    unsigned char* buf = malloc(LWS_PRE + msg_len);
    if (!buf) {
        free(msg);
        return NOSTR_ERR_MEMORY;
    }
    
    memcpy(&buf[LWS_PRE], msg, msg_len);
    
    int result = lws_write(ctx->wsi, &buf[LWS_PRE], msg_len, LWS_WRITE_TEXT);
    
    free(msg);
    free(buf);
    
    return (result < 0) ? NOSTR_ERR_CONNECTION : NOSTR_OK;
}

nostr_error_t nostr_publish_event(nostr_relay* relay, const nostr_event* event) {
    return nostr_relay_send_event(relay, event);
}

nostr_error_t nostr_relay_set_message_callback(nostr_relay* relay, nostr_message_callback callback, void* user_data) {
    if (!relay) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    relay->message_callback = callback;
    relay->message_user_data = user_data;
    
    if (relay->ws_handle) {
        relay_context* ctx = (relay_context*)relay->ws_handle;
        ctx->message_callback = callback;
        ctx->message_user_data = user_data;
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_relay_unsubscribe(nostr_relay* relay, const char* subscription_id) {
    if (!relay || !subscription_id || relay->state != NOSTR_RELAY_CONNECTED) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    relay_context* ctx = (relay_context*)relay->ws_handle;
    if (!ctx || !ctx->wsi) {
        return NOSTR_ERR_CONNECTION;
    }

    subscription_t** sub_ptr = &ctx->subscriptions;
    while (*sub_ptr) {
        if (strcmp((*sub_ptr)->id, subscription_id) == 0) {
            subscription_t* to_remove = *sub_ptr;
            *sub_ptr = to_remove->next;
            free(to_remove->id);
            free(to_remove);
            break;
        }
        sub_ptr = &(*sub_ptr)->next;
    }

    char* msg = malloc(strlen(subscription_id) + 20);
    if (!msg) {
        return NOSTR_ERR_MEMORY;
    }
    
    sprintf(msg, "[\"CLOSE\",\"%s\"]", subscription_id);
    
    size_t msg_len = strlen(msg);
    unsigned char* buf = malloc(LWS_PRE + msg_len);
    if (!buf) {
        free(msg);
        return NOSTR_ERR_MEMORY;
    }
    
    memcpy(&buf[LWS_PRE], msg, msg_len);
    
    int result = lws_write(ctx->wsi, &buf[LWS_PRE], msg_len, LWS_WRITE_TEXT);
    
    free(msg);
    free(buf);
    
    return (result < 0) ? NOSTR_ERR_CONNECTION : NOSTR_OK;
}

static int callback_nostr_relay(struct lws* wsi, enum lws_callback_reasons reason,
                               void* user, void* in, size_t len) {
    nostr_relay* relay = (nostr_relay*)lws_get_opaque_user_data(wsi);
    relay_context* ctx = relay ? (relay_context*)relay->ws_handle : NULL;
    
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            if (relay && ctx) {
                relay->state = NOSTR_RELAY_CONNECTED;
                if (ctx->state_callback) {
                    ctx->state_callback(relay, NOSTR_RELAY_CONNECTED, ctx->user_data);
                }
            }
            break;
            
        case LWS_CALLBACK_CLIENT_RECEIVE:
            if (relay && ctx && in && len > 0) {
                if (ctx->buffer_pos + len >= ctx->buffer_size) {
                    size_t new_size = ctx->buffer_pos + len + 1024;
                    char* new_buffer = realloc(ctx->receive_buffer, new_size);
                    if (!new_buffer) break;
                    ctx->receive_buffer = new_buffer;
                    ctx->buffer_size = new_size;
                }
                
                memcpy(ctx->receive_buffer + ctx->buffer_pos, in, len);
                ctx->buffer_pos += len;
                ctx->receive_buffer[ctx->buffer_pos] = '\0';
                
                char* start = ctx->receive_buffer;
                char* end;
                
                while ((end = strchr(start, '\n')) != NULL || (end = strchr(start, ']')) != NULL) {
                    if (*end == ']') end++;
                    *end = '\0';
                    
                    cJSON* json = cJSON_Parse(start);
                    if (json && cJSON_IsArray(json)) {
                        int array_size = cJSON_GetArraySize(json);
                        if (array_size >= 2) {
                            cJSON* type_item = cJSON_GetArrayItem(json, 0);
                            if (cJSON_IsString(type_item)) {
                                const char* msg_type = type_item->valuestring;
                                
                                if (strcmp(msg_type, "EVENT") == 0 && array_size >= 3) {
                                    cJSON* sub_id = cJSON_GetArrayItem(json, 1);
                                    cJSON* event_json = cJSON_GetArrayItem(json, 2);
                                    if (cJSON_IsString(sub_id) && event_json) {
                                        subscription_t* sub = ctx->subscriptions;
                                        while (sub) {
                                            if (strcmp(sub->id, sub_id->valuestring) == 0) {
                                                char* event_str = cJSON_Print(event_json);
                                                if (event_str) {
                                                    nostr_event* event;
                                                    if (nostr_event_from_json(event_str, &event) == NOSTR_OK) {
                                                        if (sub->callback) {
                                                            sub->callback(event, sub->user_data);
                                                        }
                                                        nostr_event_destroy(event);
                                                    }
                                                    free(event_str);
                                                }
                                                break;
                                            }
                                            sub = sub->next;
                                        }
                                    }
                                } else if (strcmp(msg_type, "OK") == 0 && array_size >= 4) {
                                    if (ctx->message_callback) {
                                        char* msg_str = cJSON_Print(json);
                                        if (msg_str) {
                                            ctx->message_callback(msg_type, msg_str, ctx->message_user_data);
                                            free(msg_str);
                                        }
                                    }
                                } else if (strcmp(msg_type, "EOSE") == 0 && array_size >= 2) {
                                    if (ctx->message_callback) {
                                        char* msg_str = cJSON_Print(json);
                                        if (msg_str) {
                                            ctx->message_callback(msg_type, msg_str, ctx->message_user_data);
                                            free(msg_str);
                                        }
                                    }
                                } else if (strcmp(msg_type, "CLOSED") == 0 && array_size >= 3) {
                                    cJSON* sub_id = cJSON_GetArrayItem(json, 1);
                                    if (cJSON_IsString(sub_id)) {
                                        subscription_t** sub_ptr = &ctx->subscriptions;
                                        while (*sub_ptr) {
                                            if (strcmp((*sub_ptr)->id, sub_id->valuestring) == 0) {
                                                subscription_t* to_remove = *sub_ptr;
                                                *sub_ptr = to_remove->next;
                                                free(to_remove->id);
                                                free(to_remove);
                                                break;
                                            }
                                            sub_ptr = &(*sub_ptr)->next;
                                        }
                                    }
                                    if (ctx->message_callback) {
                                        char* msg_str = cJSON_Print(json);
                                        if (msg_str) {
                                            ctx->message_callback(msg_type, msg_str, ctx->message_user_data);
                                            free(msg_str);
                                        }
                                    }
                                } else if (strcmp(msg_type, "NOTICE") == 0 && array_size >= 2) {
                                    if (ctx->message_callback) {
                                        char* msg_str = cJSON_Print(json);
                                        if (msg_str) {
                                            ctx->message_callback(msg_type, msg_str, ctx->message_user_data);
                                            free(msg_str);
                                        }
                                    }
                                } else if (ctx->message_callback) {
                                    char* msg_str = cJSON_Print(json);
                                    if (msg_str) {
                                        ctx->message_callback(msg_type, msg_str, ctx->message_user_data);
                                        free(msg_str);
                                    }
                                }
                            }
                        }
                    }
                    cJSON_Delete(json);
                    
                    start = end + 1;
                    while (*start && (*start == '\n' || *start == '\r')) start++;
                }
                
                size_t remaining = strlen(start);
                if (remaining > 0) {
                    memmove(ctx->receive_buffer, start, remaining + 1);
                    ctx->buffer_pos = remaining;
                } else {
                    ctx->buffer_pos = 0;
                    if (ctx->receive_buffer) ctx->receive_buffer[0] = '\0';
                }
            }
            break;
            
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        case LWS_CALLBACK_CLOSED:
            if (relay && ctx) {
                relay->state = NOSTR_RELAY_DISCONNECTED;
                if (ctx->state_callback) {
                    ctx->state_callback(relay, NOSTR_RELAY_DISCONNECTED, ctx->user_data);
                }
                
                if (ctx->reconnect_enabled) {
                    time_t now = time(NULL);
                    if (now - ctx->last_connect_attempt >= ctx->reconnect_interval) {
                        ctx->last_connect_attempt = now;
                        relay->state = NOSTR_RELAY_CONNECTING;
                        if (ctx->state_callback) {
                            ctx->state_callback(relay, NOSTR_RELAY_CONNECTING, ctx->user_data);
                        }
                    }
                }
            }
            break;
            
        default:
            break;
    }
    
    return 0;
}