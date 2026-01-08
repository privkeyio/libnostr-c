/**
 * @file relay_message.c
 * @brief NIP-01 Client/Relay message parsing and serialization
 */

#include "../include/nostr_relay_protocol.h"
#include <stdlib.h>
#include <string.h>

#ifdef NOSTR_FEATURE_JSON_ENHANCED
#include <cjson/cJSON.h>
#endif

#ifdef NOSTR_FEATURE_JSON_ENHANCED

nostr_relay_error_t nostr_client_msg_parse(const char* json, size_t json_len, nostr_client_msg_t* msg)
{
    (void)json_len;

    if (!json || !msg) {
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    memset(msg, 0, sizeof(nostr_client_msg_t));
    msg->type = NOSTR_CLIENT_MSG_UNKNOWN;

    cJSON* root = cJSON_Parse(json);
    if (!root || !cJSON_IsArray(root)) {
        if (root) cJSON_Delete(root);
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    int arr_size = cJSON_GetArraySize(root);
    if (arr_size < 1) {
        cJSON_Delete(root);
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    cJSON* msg_type = cJSON_GetArrayItem(root, 0);
    if (!cJSON_IsString(msg_type)) {
        cJSON_Delete(root);
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    const char* type_str = msg_type->valuestring;

    if (strcmp(type_str, "EVENT") == 0) {
        if (arr_size < 2) {
            cJSON_Delete(root);
            return NOSTR_RELAY_ERR_MISSING_FIELD;
        }

        cJSON* event_json = cJSON_GetArrayItem(root, 1);
        char* event_str = cJSON_PrintUnformatted(event_json);
        if (!event_str) {
            cJSON_Delete(root);
            return NOSTR_RELAY_ERR_MEMORY;
        }

        nostr_error_t err = nostr_event_from_json(event_str, &msg->data.event.event);
        free(event_str);

        if (err != NOSTR_OK) {
            cJSON_Delete(root);
            return NOSTR_RELAY_ERR_INVALID_JSON;
        }

        msg->type = NOSTR_CLIENT_MSG_EVENT;
    }
    else if (strcmp(type_str, "REQ") == 0) {
        if (arr_size < 2) {
            cJSON_Delete(root);
            return NOSTR_RELAY_ERR_MISSING_FIELD;
        }

        cJSON* sub_id = cJSON_GetArrayItem(root, 1);
        if (!cJSON_IsString(sub_id)) {
            cJSON_Delete(root);
            return NOSTR_RELAY_ERR_INVALID_SUBSCRIPTION_ID;
        }

        if (!nostr_validate_subscription_id(sub_id->valuestring)) {
            cJSON_Delete(root);
            return NOSTR_RELAY_ERR_INVALID_SUBSCRIPTION_ID;
        }

        strncpy(msg->data.req.subscription_id, sub_id->valuestring, 64);
        msg->data.req.subscription_id[64] = '\0';

        size_t filter_count = arr_size - 2;
        if (filter_count > 0) {
            msg->data.req.filters = calloc(filter_count, sizeof(nostr_filter_t));
            if (!msg->data.req.filters) {
                cJSON_Delete(root);
                return NOSTR_RELAY_ERR_MEMORY;
            }

            msg->data.req.filters_count = 0;
            for (int i = 2; i < arr_size; i++) {
                cJSON* filter_json = cJSON_GetArrayItem(root, i);
                char* filter_str = cJSON_PrintUnformatted(filter_json);
                if (!filter_str) {
                    nostr_client_msg_free(msg);
                    cJSON_Delete(root);
                    return NOSTR_RELAY_ERR_MEMORY;
                }

                nostr_relay_error_t err = nostr_filter_parse(filter_str, strlen(filter_str),
                                                             &msg->data.req.filters[msg->data.req.filters_count]);
                free(filter_str);

                if (err != NOSTR_RELAY_OK) {
                    nostr_client_msg_free(msg);
                    cJSON_Delete(root);
                    return err;
                }
                msg->data.req.filters_count++;
            }
        }

        msg->type = NOSTR_CLIENT_MSG_REQ;
    }
    else if (strcmp(type_str, "CLOSE") == 0) {
        if (arr_size < 2) {
            cJSON_Delete(root);
            return NOSTR_RELAY_ERR_MISSING_FIELD;
        }

        cJSON* sub_id = cJSON_GetArrayItem(root, 1);
        if (!cJSON_IsString(sub_id)) {
            cJSON_Delete(root);
            return NOSTR_RELAY_ERR_INVALID_SUBSCRIPTION_ID;
        }

        if (!nostr_validate_subscription_id(sub_id->valuestring)) {
            cJSON_Delete(root);
            return NOSTR_RELAY_ERR_INVALID_SUBSCRIPTION_ID;
        }

        strncpy(msg->data.close.subscription_id, sub_id->valuestring, 64);
        msg->data.close.subscription_id[64] = '\0';

        msg->type = NOSTR_CLIENT_MSG_CLOSE;
    }
    else if (strcmp(type_str, "AUTH") == 0) {
        if (arr_size < 2) {
            cJSON_Delete(root);
            return NOSTR_RELAY_ERR_MISSING_FIELD;
        }

        cJSON* event_json = cJSON_GetArrayItem(root, 1);
        char* event_str = cJSON_PrintUnformatted(event_json);
        if (!event_str) {
            cJSON_Delete(root);
            return NOSTR_RELAY_ERR_MEMORY;
        }

        nostr_error_t err = nostr_event_from_json(event_str, &msg->data.auth.event);
        free(event_str);

        if (err != NOSTR_OK) {
            cJSON_Delete(root);
            return NOSTR_RELAY_ERR_INVALID_JSON;
        }

        msg->type = NOSTR_CLIENT_MSG_AUTH;
    }
    else {
        cJSON_Delete(root);
        return NOSTR_RELAY_ERR_UNKNOWN_MESSAGE_TYPE;
    }

    cJSON_Delete(root);
    return NOSTR_RELAY_OK;
}

#else

nostr_relay_error_t nostr_client_msg_parse(const char* json, size_t json_len, nostr_client_msg_t* msg)
{
    (void)json;
    (void)json_len;
    (void)msg;
    return NOSTR_RELAY_ERR_INVALID_JSON;
}

#endif

void nostr_client_msg_free(nostr_client_msg_t* msg)
{
    if (!msg) return;

    switch (msg->type) {
        case NOSTR_CLIENT_MSG_EVENT:
            if (msg->data.event.event) {
                nostr_event_destroy(msg->data.event.event);
            }
            break;
        case NOSTR_CLIENT_MSG_REQ:
            if (msg->data.req.filters) {
                for (size_t i = 0; i < msg->data.req.filters_count; i++) {
                    nostr_filter_free(&msg->data.req.filters[i]);
                }
                free(msg->data.req.filters);
            }
            break;
        case NOSTR_CLIENT_MSG_AUTH:
            if (msg->data.auth.event) {
                nostr_event_destroy(msg->data.auth.event);
            }
            break;
        case NOSTR_CLIENT_MSG_CLOSE:
        case NOSTR_CLIENT_MSG_UNKNOWN:
            break;
    }

    memset(msg, 0, sizeof(nostr_client_msg_t));
}

void nostr_relay_msg_event(nostr_relay_msg_t* msg, const char* sub_id, const nostr_event* event)
{
    if (!msg) return;
    memset(msg, 0, sizeof(nostr_relay_msg_t));
    msg->type = NOSTR_RELAY_MSG_EVENT;
    if (sub_id) {
        strncpy(msg->data.event.subscription_id, sub_id, 64);
        msg->data.event.subscription_id[64] = '\0';
    }
    msg->data.event.event = event;
}

void nostr_relay_msg_ok(nostr_relay_msg_t* msg, const char* event_id, bool success, const char* message)
{
    if (!msg) return;
    memset(msg, 0, sizeof(nostr_relay_msg_t));
    msg->type = NOSTR_RELAY_MSG_OK;
    if (event_id) {
        strncpy(msg->data.ok.event_id, event_id, 64);
        msg->data.ok.event_id[64] = '\0';
    }
    msg->data.ok.success = success;
    if (message) {
        strncpy(msg->data.ok.message, message, 255);
        msg->data.ok.message[255] = '\0';
    }
}

void nostr_relay_msg_eose(nostr_relay_msg_t* msg, const char* sub_id)
{
    if (!msg) return;
    memset(msg, 0, sizeof(nostr_relay_msg_t));
    msg->type = NOSTR_RELAY_MSG_EOSE;
    if (sub_id) {
        strncpy(msg->data.eose.subscription_id, sub_id, 64);
        msg->data.eose.subscription_id[64] = '\0';
    }
}

void nostr_relay_msg_closed(nostr_relay_msg_t* msg, const char* sub_id, const char* message)
{
    if (!msg) return;
    memset(msg, 0, sizeof(nostr_relay_msg_t));
    msg->type = NOSTR_RELAY_MSG_CLOSED;
    if (sub_id) {
        strncpy(msg->data.closed.subscription_id, sub_id, 64);
        msg->data.closed.subscription_id[64] = '\0';
    }
    if (message) {
        strncpy(msg->data.closed.message, message, 255);
        msg->data.closed.message[255] = '\0';
    }
}

void nostr_relay_msg_notice(nostr_relay_msg_t* msg, const char* message)
{
    if (!msg) return;
    memset(msg, 0, sizeof(nostr_relay_msg_t));
    msg->type = NOSTR_RELAY_MSG_NOTICE;
    if (message) {
        strncpy(msg->data.notice.message, message, 255);
        msg->data.notice.message[255] = '\0';
    }
}

void nostr_relay_msg_auth(nostr_relay_msg_t* msg, const char* challenge)
{
    if (!msg) return;
    memset(msg, 0, sizeof(nostr_relay_msg_t));
    msg->type = NOSTR_RELAY_MSG_AUTH;
    if (challenge) {
        strncpy(msg->data.auth.challenge, challenge, 127);
        msg->data.auth.challenge[127] = '\0';
    }
}

#ifdef NOSTR_FEATURE_JSON_ENHANCED

nostr_relay_error_t nostr_relay_msg_serialize(const nostr_relay_msg_t* msg, char* buf, size_t buf_size, size_t* out_len)
{
    if (!msg || !buf || buf_size == 0) {
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    cJSON* root = cJSON_CreateArray();
    if (!root) {
        return NOSTR_RELAY_ERR_MEMORY;
    }

    switch (msg->type) {
        case NOSTR_RELAY_MSG_EVENT: {
            cJSON_AddItemToArray(root, cJSON_CreateString("EVENT"));
            cJSON_AddItemToArray(root, cJSON_CreateString(msg->data.event.subscription_id));

            if (!msg->data.event.event) {
                cJSON_Delete(root);
                return NOSTR_RELAY_ERR_MISSING_FIELD;
            }
            char* event_json = NULL;
            if (nostr_event_to_json(msg->data.event.event, &event_json) != NOSTR_OK || !event_json) {
                cJSON_Delete(root);
                return NOSTR_RELAY_ERR_MEMORY;
            }
            cJSON* event_obj = cJSON_Parse(event_json);
            free(event_json);
            if (!event_obj) {
                cJSON_Delete(root);
                return NOSTR_RELAY_ERR_MEMORY;
            }
            cJSON_AddItemToArray(root, event_obj);
            break;
        }

        case NOSTR_RELAY_MSG_OK:
            cJSON_AddItemToArray(root, cJSON_CreateString("OK"));
            cJSON_AddItemToArray(root, cJSON_CreateString(msg->data.ok.event_id));
            cJSON_AddItemToArray(root, cJSON_CreateBool(msg->data.ok.success));
            cJSON_AddItemToArray(root, cJSON_CreateString(msg->data.ok.message));
            break;

        case NOSTR_RELAY_MSG_EOSE:
            cJSON_AddItemToArray(root, cJSON_CreateString("EOSE"));
            cJSON_AddItemToArray(root, cJSON_CreateString(msg->data.eose.subscription_id));
            break;

        case NOSTR_RELAY_MSG_CLOSED:
            cJSON_AddItemToArray(root, cJSON_CreateString("CLOSED"));
            cJSON_AddItemToArray(root, cJSON_CreateString(msg->data.closed.subscription_id));
            cJSON_AddItemToArray(root, cJSON_CreateString(msg->data.closed.message));
            break;

        case NOSTR_RELAY_MSG_NOTICE:
            cJSON_AddItemToArray(root, cJSON_CreateString("NOTICE"));
            cJSON_AddItemToArray(root, cJSON_CreateString(msg->data.notice.message));
            break;

        case NOSTR_RELAY_MSG_AUTH:
            cJSON_AddItemToArray(root, cJSON_CreateString("AUTH"));
            cJSON_AddItemToArray(root, cJSON_CreateString(msg->data.auth.challenge));
            break;

        default:
            cJSON_Delete(root);
            return NOSTR_RELAY_ERR_UNKNOWN_MESSAGE_TYPE;
    }

    char* json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json_str) {
        return NOSTR_RELAY_ERR_MEMORY;
    }

    size_t len = strlen(json_str);
    if (len >= buf_size) {
        free(json_str);
        if (out_len) *out_len = len;
        return NOSTR_RELAY_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(buf, json_str, len + 1);
    free(json_str);

    if (out_len) *out_len = len;
    return NOSTR_RELAY_OK;
}

#else

nostr_relay_error_t nostr_relay_msg_serialize(const nostr_relay_msg_t* msg, char* buf, size_t buf_size, size_t* out_len)
{
    (void)msg;
    (void)buf;
    (void)buf_size;
    (void)out_len;
    return NOSTR_RELAY_ERR_INVALID_JSON;
}

#endif

nostr_client_msg_type_t nostr_client_msg_get_type(const nostr_client_msg_t* msg)
{
    if (!msg) return NOSTR_CLIENT_MSG_UNKNOWN;
    return msg->type;
}

const nostr_event* nostr_client_msg_get_event(const nostr_client_msg_t* msg)
{
    if (!msg) return NULL;

    switch (msg->type) {
        case NOSTR_CLIENT_MSG_EVENT:
            return msg->data.event.event;
        case NOSTR_CLIENT_MSG_AUTH:
            return msg->data.auth.event;
        default:
            return NULL;
    }
}

const char* nostr_client_msg_get_subscription_id(const nostr_client_msg_t* msg)
{
    if (!msg) return NULL;

    switch (msg->type) {
        case NOSTR_CLIENT_MSG_REQ:
            return msg->data.req.subscription_id;
        case NOSTR_CLIENT_MSG_CLOSE:
            return msg->data.close.subscription_id;
        default:
            return NULL;
    }
}

const nostr_filter_t* nostr_client_msg_get_filters(const nostr_client_msg_t* msg, size_t* out_count)
{
    if (!msg || msg->type != NOSTR_CLIENT_MSG_REQ) {
        if (out_count) *out_count = 0;
        return NULL;
    }
    if (out_count) *out_count = msg->data.req.filters_count;
    return msg->data.req.filters;
}
