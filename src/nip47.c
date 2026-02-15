#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <openssl/rand.h>
#include "../include/nostr.h"

#ifdef NOSTR_FEATURE_NIP47

#ifdef NOSTR_FEATURE_JSON_ENHANCED
#include <cjson/cJSON.h>
#endif

#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
#include <noscrypt.h>
#else
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#endif

#define NWC_KIND_INFO 13194
#define NWC_KIND_REQUEST 23194
#define NWC_KIND_RESPONSE 23195
#define NWC_KIND_NOTIFICATION_LEGACY 23196
#define NWC_KIND_NOTIFICATION 23197

static size_t nip47_json_escape(char* dest, size_t dest_size, const char* src)
{
    size_t pos = 0;
    for (size_t i = 0; src[i] && pos < dest_size - 1; i++) {
        switch (src[i]) {
            case '"': case '\\':
                if (pos + 2 > dest_size - 1) goto done;
                dest[pos++] = '\\';
                dest[pos++] = src[i];
                break;
            case '\n':
                if (pos + 2 > dest_size - 1) goto done;
                dest[pos++] = '\\'; dest[pos++] = 'n';
                break;
            case '\r':
                if (pos + 2 > dest_size - 1) goto done;
                dest[pos++] = '\\'; dest[pos++] = 'r';
                break;
            case '\t':
                if (pos + 2 > dest_size - 1) goto done;
                dest[pos++] = '\\'; dest[pos++] = 't';
                break;
            default:
                dest[pos++] = src[i];
                break;
        }
    }
done:
    dest[pos] = '\0';
    return pos;
}

struct nwc_connection {
    char** relays;
    size_t relay_count;
    nostr_privkey secret;
    nostr_key service_pubkey;
    char* lud16;
};

typedef struct {
    const char* method;
    void* params;
} nwc_request_t;

typedef struct {
    const char* result_type;
    void* result;
    struct {
        char* code;
        char* message;
    } error;
} nwc_response_t;

typedef struct {
    const char* notification_type;
    void* notification;
} nwc_notification_t;

static void free_connection(struct nwc_connection* conn)
{
    if (!conn) return;
    
    if (conn->relays) {
        for (size_t i = 0; i < conn->relay_count; i++) {
            free(conn->relays[i]);
        }
        free(conn->relays);
    }
    
    if (conn->lud16) {
        free(conn->lud16);
    }
    
    secure_wipe(&conn->secret, sizeof(nostr_privkey));
    free(conn);
}

static int hex_decode(const char* hex, uint8_t* out, size_t out_len)
{
    if (strlen(hex) != out_len * 2) return -1;
    
    for (size_t i = 0; i < out_len; i++) {
        char byte[3] = {hex[i*2], hex[i*2+1], 0};
        char* end;
        long val = strtol(byte, &end, 16);
        if (end != byte + 2) return -1;
        out[i] = (uint8_t)val;
    }
    
    return 0;
}

static char* url_decode(const char* src)
{
    if (!src) return NULL;
    
    size_t len = strlen(src);
    char* dst = malloc(len + 1);
    if (!dst) return NULL;
    
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (src[i] == '%' && i + 2 < len) {
            char hex[3] = {src[i+1], src[i+2], 0};
            char* end;
            long val = strtol(hex, &end, 16);
            if (end == hex + 2) {
                dst[j++] = (char)val;
                i += 2;
                continue;
            }
        }
        dst[j++] = src[i];
    }
    dst[j] = 0;
    
    return dst;
}

nostr_error_t nostr_nip47_parse_connection_uri(const char* uri, struct nwc_connection** connection)
{
    if (!uri || !connection) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    const char* prefix = "nostr+walletconnect://";
    if (strncmp(uri, prefix, strlen(prefix)) != 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    const char* start = uri + strlen(prefix);
    const char* query = strchr(start, '?');
    if (!query || query - start != 64) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    struct nwc_connection* conn = calloc(1, sizeof(struct nwc_connection));
    if (!conn) {
        return NOSTR_ERR_MEMORY;
    }
    
    char pubkey_hex[65] = {0};
    memcpy(pubkey_hex, start, 64);
    if (hex_decode(pubkey_hex, conn->service_pubkey.data, 32) != 0) {
        free_connection(conn);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    query++;
    char* params = strdup(query);
    if (!params) {
        free_connection(conn);
        return NOSTR_ERR_MEMORY;
    }
    
    size_t relay_cap = 4;
    conn->relays = malloc(relay_cap * sizeof(char*));
    if (!conn->relays) {
        free(params);
        free_connection(conn);
        return NOSTR_ERR_MEMORY;
    }
    
    int has_secret = 0;
    char* saveptr;
    char* param = strtok_r(params, "&", &saveptr);
    
    while (param) {
        char* eq = strchr(param, '=');
        if (eq) {
            *eq = 0;
            char* value = eq + 1;
            
            if (strcmp(param, "relay") == 0) {
                if (conn->relay_count >= relay_cap) {
                    relay_cap *= 2;
                    char** new_relays = realloc(conn->relays, relay_cap * sizeof(char*));
                    if (!new_relays) {
                        free(params);
                        free_connection(conn);
                        return NOSTR_ERR_MEMORY;
                    }
                    conn->relays = new_relays;
                }
                
                conn->relays[conn->relay_count] = url_decode(value);
                if (!conn->relays[conn->relay_count]) {
                    free(params);
                    free_connection(conn);
                    return NOSTR_ERR_MEMORY;
                }
                conn->relay_count++;
            }
            else if (strcmp(param, "secret") == 0) {
                if (strlen(value) != 64) {
                    free(params);
                    free_connection(conn);
                    return NOSTR_ERR_INVALID_PARAM;
                }
                if (hex_decode(value, conn->secret.data, 32) != 0) {
                    free(params);
                    free_connection(conn);
                    return NOSTR_ERR_INVALID_PARAM;
                }
                has_secret = 1;
            }
            else if (strcmp(param, "lud16") == 0) {
                conn->lud16 = url_decode(value);
                if (!conn->lud16) {
                    free(params);
                    free_connection(conn);
                    return NOSTR_ERR_MEMORY;
                }
            }
        }
        
        param = strtok_r(NULL, "&", &saveptr);
    }
    
    free(params);
    
    if (!has_secret || conn->relay_count == 0) {
        free_connection(conn);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    *connection = conn;
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_parse_info_event(const nostr_event* event, char*** capabilities, 
                                           size_t* cap_count, char*** notifications, 
                                           size_t* notif_count, char*** encryptions,
                                           size_t* enc_count)
{
    if (!event || event->kind != NWC_KIND_INFO) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (capabilities && cap_count) {
        char* content = strdup(event->content);
        if (!content) {
            return NOSTR_ERR_MEMORY;
        }
        
        *cap_count = 0;
        for (char* p = content; *p; p++) {
            if (*p == ' ') (*cap_count)++;
        }
        (*cap_count)++;
        
        *capabilities = malloc(*cap_count * sizeof(char*));
        if (!*capabilities) {
            free(content);
            return NOSTR_ERR_MEMORY;
        }
        
        size_t i = 0;
        char* saveptr;
        char* cap = strtok_r(content, " ", &saveptr);
        while (cap && i < *cap_count) {
            (*capabilities)[i] = strdup(cap);
            if (!(*capabilities)[i]) {
                for (size_t j = 0; j < i; j++) {
                    free((*capabilities)[j]);
                }
                free(*capabilities);
                free(content);
                return NOSTR_ERR_MEMORY;
            }
            i++;
            cap = strtok_r(NULL, " ", &saveptr);
        }
        *cap_count = i;
        
        free(content);
    }
    
    if (notifications && notif_count) {
        *notifications = NULL;
        *notif_count = 0;
        
        for (size_t i = 0; i < event->tags_count; i++) {
            if (event->tags[i].count >= 2 && 
                strcmp(event->tags[i].values[0], "notifications") == 0) {
                
                char* notif_str = strdup(event->tags[i].values[1]);
                if (!notif_str) {
                    return NOSTR_ERR_MEMORY;
                }
                
                *notif_count = 0;
                for (char* p = notif_str; *p; p++) {
                    if (*p == ' ') (*notif_count)++;
                }
                (*notif_count)++;
                
                *notifications = malloc(*notif_count * sizeof(char*));
                if (!*notifications) {
                    free(notif_str);
                    return NOSTR_ERR_MEMORY;
                }
                
                size_t j = 0;
                char* saveptr;
                char* notif = strtok_r(notif_str, " ", &saveptr);
                while (notif && j < *notif_count) {
                    (*notifications)[j] = strdup(notif);
                    if (!(*notifications)[j]) {
                        for (size_t k = 0; k < j; k++) {
                            free((*notifications)[k]);
                        }
                        free(*notifications);
                        free(notif_str);
                        return NOSTR_ERR_MEMORY;
                    }
                    j++;
                    notif = strtok_r(NULL, " ", &saveptr);
                }
                *notif_count = j;
                
                free(notif_str);
                break;
            }
        }
    }
    
    if (encryptions && enc_count) {
        *encryptions = NULL;
        *enc_count = 0;
        
        for (size_t i = 0; i < event->tags_count; i++) {
            if (event->tags[i].count >= 2 && 
                strcmp(event->tags[i].values[0], "encryption") == 0) {
                
                char* enc_str = strdup(event->tags[i].values[1]);
                if (!enc_str) {
                    return NOSTR_ERR_MEMORY;
                }
                
                *enc_count = 0;
                for (char* p = enc_str; *p; p++) {
                    if (*p == ' ') (*enc_count)++;
                }
                (*enc_count)++;
                
                *encryptions = malloc(*enc_count * sizeof(char*));
                if (!*encryptions) {
                    free(enc_str);
                    return NOSTR_ERR_MEMORY;
                }
                
                size_t j = 0;
                char* saveptr;
                char* enc = strtok_r(enc_str, " ", &saveptr);
                while (enc && j < *enc_count) {
                    (*encryptions)[j] = strdup(enc);
                    if (!(*encryptions)[j]) {
                        for (size_t k = 0; k < j; k++) {
                            free((*encryptions)[k]);
                        }
                        free(*encryptions);
                        free(enc_str);
                        return NOSTR_ERR_MEMORY;
                    }
                    j++;
                    enc = strtok_r(NULL, " ", &saveptr);
                }
                *enc_count = j;
                
                free(enc_str);
                break;
            }
        }
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_create_request_event(nostr_event** event, const struct nwc_connection* conn,
                                               const char* method, const char* params_json,
                                               int use_nip44)
{
    if (!event || !conn || !method || !params_json) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    nostr_error_t err = nostr_event_create(event);
    if (err != NOSTR_OK) {
        return err;
    }
    
    (*event)->kind = NWC_KIND_REQUEST;
    (*event)->created_at = time(NULL);
    
    nostr_key client_pubkey;
    // Derive public key from private key
    {
#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
        NCPublicKey nc_public;
        NCSecretKey nc_secret;
        memcpy(nc_secret.key, conn->secret.data, NC_SEC_KEY_SIZE);
        extern NCContext* nc_ctx;
        if (NCGetPublicKey(nc_ctx, &nc_secret, &nc_public) != NC_SUCCESS) {
            nostr_event_destroy(*event);
            *event = NULL;
            return NOSTR_ERR_INVALID_KEY;
        }
        memcpy(client_pubkey.data, nc_public.key, NOSTR_PUBKEY_SIZE);
#else
        extern secp256k1_context* secp256k1_ctx;
        secp256k1_pubkey pubkey_internal;
        if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey_internal, conn->secret.data)) {
            nostr_event_destroy(*event);
            *event = NULL;
            return NOSTR_ERR_INVALID_KEY;
        }
        secp256k1_xonly_pubkey xonly_pubkey;
        int parity;
        if (!secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &xonly_pubkey, &parity, &pubkey_internal)) {
            nostr_event_destroy(*event);
            *event = NULL;
            return NOSTR_ERR_INVALID_KEY;
        }
        if (!secp256k1_xonly_pubkey_serialize(secp256k1_ctx, client_pubkey.data, &xonly_pubkey)) {
            nostr_event_destroy(*event);
            *event = NULL;
            return NOSTR_ERR_INVALID_KEY;
        }
#endif
    }
    if (err != NOSTR_OK) {
        nostr_event_destroy(*event);
        *event = NULL;
        return err;
    }
    
    memcpy(&(*event)->pubkey, &client_pubkey, sizeof(nostr_key));
    
    char pubkey_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(pubkey_hex + i*2, "%02x", conn->service_pubkey.data[i]);
    }
    pubkey_hex[64] = 0;
    
    const char* p_tag[2] = {"p", pubkey_hex};
    err = nostr_event_add_tag(*event, p_tag, 2);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*event);
        *event = NULL;
        return err;
    }
    
    if (use_nip44) {
        const char* enc_tag[2] = {"encryption", "nip44_v2"};
        err = nostr_event_add_tag(*event, enc_tag, 2);
        if (err != NOSTR_OK) {
            nostr_event_destroy(*event);
            *event = NULL;
            return err;
        }
    }
    
    char escaped_method[256];
    size_t em_pos = 0;
    for (size_t i = 0; method[i] && em_pos < sizeof(escaped_method) - 2; i++) {
        if (method[i] == '"' || method[i] == '\\') {
            escaped_method[em_pos++] = '\\';
        }
        escaped_method[em_pos++] = method[i];
    }
    escaped_method[em_pos] = '\0';

#ifdef HAVE_CJSON
    {
        cJSON* params_parsed = cJSON_Parse(params_json);
        if (!params_parsed) {
            nostr_event_destroy(*event);
            *event = NULL;
            return NOSTR_ERR_INVALID_PARAM;
        }
        cJSON_Delete(params_parsed);
    }
#else
    if (params_json[0] != '{' && params_json[0] != '[') {
        nostr_event_destroy(*event);
        *event = NULL;
        return NOSTR_ERR_INVALID_PARAM;
    }
#endif

    char payload[8192];
    snprintf(payload, sizeof(payload), "{\"method\":\"%s\",\"params\":%s}", escaped_method, params_json);
    
    char* encrypted = NULL;
    if (use_nip44) {
        err = nostr_nip44_encrypt(&conn->secret, &conn->service_pubkey, payload, strlen(payload), &encrypted);
        if (err == NOSTR_OK) {
            err = nostr_event_set_content(*event, encrypted);
            free(encrypted);
        }
    } else {
        // NIP-04 not implemented in base library
        err = NOSTR_ERR_NOT_SUPPORTED;
    }
    
    if (err != NOSTR_OK) {
        nostr_event_destroy(*event);
        *event = NULL;
        return err;
    }
    
    err = nostr_event_compute_id(*event);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*event);
        *event = NULL;
        return err;
    }
    
    err = nostr_event_sign(*event, &conn->secret);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*event);
        *event = NULL;
        return err;
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_parse_response_event(const nostr_event* event, const nostr_privkey* client_secret,
                                               char** result_type, char** result_json, 
                                               char** error_code, char** error_message)
{
    if (!event || event->kind != NWC_KIND_RESPONSE || !client_secret) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    nostr_key service_pubkey = {0};
    int found_p_tag = 0;
    
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 && strcmp(event->tags[i].values[0], "p") == 0) {
            if (hex_decode(event->tags[i].values[1], service_pubkey.data, 32) == 0) {
                found_p_tag = 1;
                break;
            }
        }
    }
    
    if (!found_p_tag) {
        memcpy(&service_pubkey, &event->pubkey, sizeof(nostr_key));
    }
    
    char* decrypted = NULL;
    nostr_error_t err;
    
    int is_nip44 = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 && strcmp(event->tags[i].values[0], "encryption") == 0) {
            if (strstr(event->tags[i].values[1], "nip44") != NULL) {
                is_nip44 = 1;
            }
            break;
        }
    }
    
    size_t decrypted_len = 0;
    if (is_nip44) {
        err = nostr_nip44_decrypt(client_secret, &service_pubkey, event->content, &decrypted, &decrypted_len);
    } else {
        // NIP-04 not implemented in base library
        err = NOSTR_ERR_NOT_SUPPORTED;
    }
    
    if (err != NOSTR_OK) {
        return err;
    }
    
    if (!decrypted) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
#ifdef HAVE_CJSON
    cJSON* root = cJSON_Parse(decrypted);
    if (!root) {
        free(decrypted);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (result_type) {
        cJSON* type_obj = cJSON_GetObjectItem(root, "result_type");
        if (type_obj && cJSON_IsString(type_obj)) {
            *result_type = strdup(type_obj->valuestring);
        }
    }
    
    if (result_json) {
        cJSON* result_obj = cJSON_GetObjectItem(root, "result");
        if (result_obj) {
            *result_json = cJSON_PrintUnformatted(result_obj);
        }
    }
    
    cJSON* error_obj = cJSON_GetObjectItem(root, "error");
    if (error_obj) {
        if (error_code) {
            cJSON* code_obj = cJSON_GetObjectItem(error_obj, "code");
            if (code_obj && cJSON_IsString(code_obj)) {
                *error_code = strdup(code_obj->valuestring);
            }
        }
        
        if (error_message) {
            cJSON* msg_obj = cJSON_GetObjectItem(error_obj, "message");
            if (msg_obj && cJSON_IsString(msg_obj)) {
                *error_message = strdup(msg_obj->valuestring);
            }
        }
    }
    
    cJSON_Delete(root);
#else
    if (result_type) *result_type = strdup("unknown");
    if (result_json) *result_json = strdup("{}");
    if (error_code) *error_code = NULL;
    if (error_message) *error_message = NULL;
#endif
    
    free(decrypted);
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_create_pay_invoice_params(char** params_json, const char* invoice, 
                                                    uint64_t* amount_msats)
{
    if (!params_json || !invoice) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
#ifdef HAVE_CJSON
    cJSON* params = cJSON_CreateObject();
    if (!params) {
        return NOSTR_ERR_MEMORY;
    }
    
    cJSON_AddStringToObject(params, "invoice", invoice);
    
    if (amount_msats) {
        cJSON_AddNumberToObject(params, "amount", *amount_msats);
    }
    
    *params_json = cJSON_PrintUnformatted(params);
    cJSON_Delete(params);
    
    if (!*params_json) {
        return NOSTR_ERR_MEMORY;
    }
#else
    char escaped_invoice[4096];
    nip47_json_escape(escaped_invoice, sizeof(escaped_invoice), invoice);
    char buffer[4096];
    if (amount_msats) {
        snprintf(buffer, sizeof(buffer), "{\"invoice\":\"%s\",\"amount\":%llu}",
                 escaped_invoice, (unsigned long long)*amount_msats);
    } else {
        snprintf(buffer, sizeof(buffer), "{\"invoice\":\"%s\"}", escaped_invoice);
    }

    *params_json = strdup(buffer);
    if (!*params_json) {
        return NOSTR_ERR_MEMORY;
    }
#endif

    return NOSTR_OK;
}

nostr_error_t nostr_nip47_create_get_balance_params(char** params_json)
{
    if (!params_json) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    *params_json = strdup("{}");
    if (!*params_json) {
        return NOSTR_ERR_MEMORY;
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_create_make_invoice_params(char** params_json, uint64_t amount_msats,
                                                     const char* description, const char* description_hash,
                                                     uint32_t* expiry_secs)
{
    if (!params_json || amount_msats == 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
#ifdef HAVE_CJSON
    cJSON* params = cJSON_CreateObject();
    if (!params) {
        return NOSTR_ERR_MEMORY;
    }
    
    cJSON_AddNumberToObject(params, "amount", amount_msats);
    
    if (description) {
        cJSON_AddStringToObject(params, "description", description);
    }
    
    if (description_hash) {
        cJSON_AddStringToObject(params, "description_hash", description_hash);
    }
    
    if (expiry_secs) {
        cJSON_AddNumberToObject(params, "expiry", *expiry_secs);
    }
    
    *params_json = cJSON_PrintUnformatted(params);
    cJSON_Delete(params);
    
    if (!*params_json) {
        return NOSTR_ERR_MEMORY;
    }
#else
    char buffer[4096];
    int offset = snprintf(buffer, sizeof(buffer), "{\"amount\":%llu",
                         (unsigned long long)amount_msats);

    if (description) {
        char escaped_desc[2048];
        nip47_json_escape(escaped_desc, sizeof(escaped_desc), description);
        offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                          ",\"description\":\"%s\"", escaped_desc);
    }

    if (description_hash) {
        char escaped_hash[2048];
        nip47_json_escape(escaped_hash, sizeof(escaped_hash), description_hash);
        offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                          ",\"description_hash\":\"%s\"", escaped_hash);
    }
    
    if (expiry_secs) {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, 
                          ",\"expiry\":%u", *expiry_secs);
    }
    
    snprintf(buffer + offset, sizeof(buffer) - offset, "}");
    
    *params_json = strdup(buffer);
    if (!*params_json) {
        return NOSTR_ERR_MEMORY;
    }
#endif
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_parse_notification_event(const nostr_event* event, const nostr_privkey* client_secret,
                                                   char** notification_type, char** notification_json)
{
    if (!event || !client_secret || 
        (event->kind != NWC_KIND_NOTIFICATION && event->kind != NWC_KIND_NOTIFICATION_LEGACY)) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    nostr_key service_pubkey;
    memcpy(&service_pubkey, &event->pubkey, sizeof(nostr_key));
    
    char* decrypted = NULL;
    nostr_error_t err;
    
    size_t decrypted_len = 0;
    if (event->kind == NWC_KIND_NOTIFICATION) {
        err = nostr_nip44_decrypt(client_secret, &service_pubkey, event->content, &decrypted, &decrypted_len);
    } else {
        // NIP-04 not implemented in base library
        err = NOSTR_ERR_NOT_SUPPORTED;
    }
    
    if (err != NOSTR_OK) {
        return err;
    }
    
    if (!decrypted) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
#ifdef HAVE_CJSON
    cJSON* root = cJSON_Parse(decrypted);
    if (!root) {
        free(decrypted);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (notification_type) {
        cJSON* type_obj = cJSON_GetObjectItem(root, "notification_type");
        if (type_obj && cJSON_IsString(type_obj)) {
            *notification_type = strdup(type_obj->valuestring);
        }
    }
    
    if (notification_json) {
        cJSON* notif_obj = cJSON_GetObjectItem(root, "notification");
        if (notif_obj) {
            *notification_json = cJSON_PrintUnformatted(notif_obj);
        }
    }
    
    cJSON_Delete(root);
#else
    if (notification_type) *notification_type = strdup("unknown");
    if (notification_json) *notification_json = strdup("{}");
#endif
    
    free(decrypted);
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_free_connection(struct nwc_connection* conn)
{
    free_connection(conn);
    return NOSTR_OK;
}

#else

/* NIP-47 functionality not available */
nostr_error_t nostr_nip47_parse_connection_uri(const char* uri, nostr_nip47_connection* connection) {
    (void)uri; (void)connection;
    return NOSTR_ERR_NOT_SUPPORTED;
}

void nostr_nip47_free_connection(nostr_nip47_connection* connection) {
    (void)connection;
}

nostr_error_t nostr_nip47_create_request_event(const nostr_nip47_connection* connection, const char* method, const char* params_json, nostr_event** request) {
    (void)connection; (void)method; (void)params_json; (void)request;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif /* NOSTR_FEATURE_NIP47 */
