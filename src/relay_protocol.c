/**
 * @file relay_protocol.c
 * @brief NIP-01 Relay-side protocol core implementation
 */

#include "../include/nostr_relay_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef NOSTR_FEATURE_JSON_ENHANCED
#include <cjson/cJSON.h>
#endif

const char* nostr_relay_error_string(nostr_relay_error_t error)
{
    switch (error) {
        case NOSTR_RELAY_OK: return "OK";
        case NOSTR_RELAY_ERR_INVALID_JSON: return "invalid JSON";
        case NOSTR_RELAY_ERR_MISSING_FIELD: return "missing required field";
        case NOSTR_RELAY_ERR_INVALID_ID: return "invalid event ID";
        case NOSTR_RELAY_ERR_INVALID_PUBKEY: return "invalid pubkey";
        case NOSTR_RELAY_ERR_INVALID_SIG: return "invalid signature";
        case NOSTR_RELAY_ERR_INVALID_CREATED_AT: return "invalid created_at";
        case NOSTR_RELAY_ERR_INVALID_KIND: return "invalid kind";
        case NOSTR_RELAY_ERR_INVALID_TAGS: return "invalid tags";
        case NOSTR_RELAY_ERR_INVALID_CONTENT: return "invalid content";
        case NOSTR_RELAY_ERR_ID_MISMATCH: return "event ID mismatch";
        case NOSTR_RELAY_ERR_SIG_MISMATCH: return "signature verification failed";
        case NOSTR_RELAY_ERR_FUTURE_EVENT: return "event created_at too far in future";
        case NOSTR_RELAY_ERR_EXPIRED_EVENT: return "event has expired";
        case NOSTR_RELAY_ERR_INVALID_SUBSCRIPTION_ID: return "invalid subscription ID";
        case NOSTR_RELAY_ERR_TOO_MANY_FILTERS: return "too many filters";
        case NOSTR_RELAY_ERR_BUFFER_TOO_SMALL: return "buffer too small";
        case NOSTR_RELAY_ERR_MEMORY: return "memory allocation failed";
        case NOSTR_RELAY_ERR_UNKNOWN_MESSAGE_TYPE: return "unknown message type";
        default: return "unknown error";
    }
}

size_t nostr_validation_error_format(const nostr_validation_result_t* result, char* buf, size_t buf_size)
{
    if (!result || !buf || buf_size == 0) {
        return 0;
    }

    const char* prefix = "invalid:";
    int len;
    if (result->error_field[0] != '\0') {
        len = snprintf(buf, buf_size, "%s %s for field '%s'",
                      prefix, result->error_message, result->error_field);
    } else {
        len = snprintf(buf, buf_size, "%s %s", prefix, result->error_message);
    }

    return (len > 0 && (size_t)len < buf_size) ? (size_t)len : 0;
}

bool nostr_validate_hex64(const char* hex)
{
    if (!hex) return false;

    size_t len = strlen(hex);
    if (len != 64) return false;

    for (size_t i = 0; i < 64; i++) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool nostr_validate_hex_prefix(const char* hex)
{
    if (!hex) return false;

    size_t len = strlen(hex);
    if (len == 0 || len > 64) return false;

    for (size_t i = 0; i < len; i++) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool nostr_validate_subscription_id(const char* sub_id)
{
    if (!sub_id) return false;

    size_t len = strlen(sub_id);
    if (len == 0 || len > 64) return false;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)sub_id[i];
        if (c < 32 || c > 126) {
            return false;
        }
    }
    return true;
}

bool nostr_validate_timestamp(int64_t timestamp, int64_t max_future_seconds)
{
    int64_t now = nostr_timestamp_now();
    return timestamp <= (now + max_future_seconds);
}

bool nostr_validate_address(const char* address)
{
    if (!address || !*address) {
        return false;
    }

    const char* first_colon = strchr(address, ':');
    if (!first_colon || first_colon == address) {
        return false;
    }

    for (const char* p = address; p < first_colon; p++) {
        if (*p < '0' || *p > '9') {
            return false;
        }
    }

    const char* pubkey_start = first_colon + 1;
    const char* second_colon = strchr(pubkey_start, ':');
    if (!second_colon) {
        return false;
    }

    size_t pubkey_len = (size_t)(second_colon - pubkey_start);
    if (pubkey_len != 64) {
        return false;
    }

    for (const char* p = pubkey_start; p < second_colon; p++) {
        char c = *p;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }

    return true;
}

int64_t nostr_timestamp_now(void)
{
    return (int64_t)time(NULL);
}

nostr_kind_type_t nostr_kind_get_type(int32_t kind)
{
    if (kind >= 20000 && kind < 30000) {
        return NOSTR_KIND_EPHEMERAL;
    }
    if (kind >= 30000 && kind < 40000) {
        return NOSTR_KIND_ADDRESSABLE;
    }
    if (kind == 0 || kind == 3 || (kind >= 10000 && kind < 20000)) {
        return NOSTR_KIND_REPLACEABLE;
    }
    return NOSTR_KIND_REGULAR;
}

bool nostr_kind_is_regular(int32_t kind)
{
    return nostr_kind_get_type(kind) == NOSTR_KIND_REGULAR;
}

bool nostr_kind_is_replaceable(int32_t kind)
{
    return nostr_kind_get_type(kind) == NOSTR_KIND_REPLACEABLE;
}

bool nostr_kind_is_ephemeral(int32_t kind)
{
    return nostr_kind_get_type(kind) == NOSTR_KIND_EPHEMERAL;
}

bool nostr_kind_is_addressable(int32_t kind)
{
    return nostr_kind_get_type(kind) == NOSTR_KIND_ADDRESSABLE;
}

const char* nostr_event_get_tag_value(const nostr_event* event, const char* tag_name)
{
    if (!event || !tag_name || !event->tags) {
        return NULL;
    }

    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 &&
            event->tags[i].values[0] &&
            strcmp(event->tags[i].values[0], tag_name) == 0) {
            return event->tags[i].values[1];
        }
    }
    return NULL;
}

const char* nostr_event_get_d_tag(const nostr_event* event)
{
    return nostr_event_get_tag_value(event, "d");
}

size_t nostr_event_get_tag_values(const nostr_event* event, const char* tag_name, const char** values, size_t max_values)
{
    if (!event || !tag_name || !values || max_values == 0 || !event->tags) {
        return 0;
    }

    size_t count = 0;
    for (size_t i = 0; i < event->tags_count && count < max_values; i++) {
        if (event->tags[i].count >= 2 &&
            event->tags[i].values[0] &&
            strcmp(event->tags[i].values[0], tag_name) == 0) {
            values[count++] = event->tags[i].values[1];
        }
    }
    return count;
}

bool nostr_event_has_tag(const nostr_event* event, const char* tag_name)
{
    if (!event || !tag_name || !event->tags) {
        return false;
    }

    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 1 &&
            event->tags[i].values[0] &&
            strcmp(event->tags[i].values[0], tag_name) == 0) {
            return true;
        }
    }
    return false;
}

const char** nostr_event_get_tag_at(const nostr_event* event, size_t index, size_t* out_count)
{
    if (!event || !event->tags || index >= event->tags_count) {
        if (out_count) *out_count = 0;
        return NULL;
    }

    if (out_count) {
        *out_count = event->tags[index].count;
    }
    return (const char**)event->tags[index].values;
}

int64_t nostr_event_get_expiration(const nostr_event* event)
{
    const char* exp_str = nostr_event_get_tag_value(event, "expiration");
    if (!exp_str) {
        return 0;
    }

    char* endptr;
    int64_t expiration = strtoll(exp_str, &endptr, 10);
    if (*endptr != '\0' || expiration < 0) {
        return 0;
    }
    return expiration;
}

bool nostr_event_is_expired(const nostr_event* event, int64_t now)
{
    int64_t expiration = nostr_event_get_expiration(event);
    if (expiration == 0) {
        return false;
    }
    return now > expiration;
}

bool nostr_event_is_expired_now(const nostr_event* event)
{
    return nostr_event_is_expired(event, nostr_timestamp_now());
}

#ifdef NOSTR_FEATURE_JSON_ENHANCED

nostr_relay_error_t nostr_event_parse(const char* json, size_t json_len, nostr_event** event)
{
    (void)json_len;

    if (!json || !event) {
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    nostr_error_t err = nostr_event_from_json(json, event);

    switch (err) {
        case NOSTR_OK:
            return NOSTR_RELAY_OK;
        case NOSTR_ERR_JSON_PARSE:
            return NOSTR_RELAY_ERR_INVALID_JSON;
        case NOSTR_ERR_MEMORY:
            return NOSTR_RELAY_ERR_MEMORY;
        case NOSTR_ERR_INVALID_EVENT:
            return NOSTR_RELAY_ERR_INVALID_ID;
        default:
            return NOSTR_RELAY_ERR_INVALID_JSON;
    }
}

nostr_relay_error_t nostr_event_serialize_canonical(const nostr_event* event, char* buf, size_t buf_size, size_t* out_len)
{
    if (!event || !buf || buf_size == 0) {
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    char pubkey_hex[65];
    for (int i = 0; i < NOSTR_PUBKEY_SIZE; i++) {
        sprintf(pubkey_hex + i * 2, "%02x", event->pubkey.data[i]);
    }
    pubkey_hex[64] = '\0';

    cJSON* serialization = cJSON_CreateArray();
    if (!serialization) {
        return NOSTR_RELAY_ERR_MEMORY;
    }

    cJSON_AddItemToArray(serialization, cJSON_CreateNumber(0));
    cJSON_AddItemToArray(serialization, cJSON_CreateString(pubkey_hex));
    cJSON_AddItemToArray(serialization, cJSON_CreateNumber((double)event->created_at));
    cJSON_AddItemToArray(serialization, cJSON_CreateNumber(event->kind));

    cJSON* tags_array = cJSON_CreateArray();
    for (size_t i = 0; i < event->tags_count; i++) {
        cJSON* tag_array = cJSON_CreateArray();
        for (size_t j = 0; j < event->tags[i].count; j++) {
            const char* tag_value = event->tags[i].values[j] ? event->tags[i].values[j] : "";
            cJSON_AddItemToArray(tag_array, cJSON_CreateString(tag_value));
        }
        cJSON_AddItemToArray(tags_array, tag_array);
    }
    cJSON_AddItemToArray(serialization, tags_array);

    cJSON_AddItemToArray(serialization, cJSON_CreateString(event->content ? event->content : ""));

    char* json_str = cJSON_PrintUnformatted(serialization);
    cJSON_Delete(serialization);

    if (!json_str) {
        return NOSTR_RELAY_ERR_MEMORY;
    }

    size_t len = strlen(json_str);
    if (out_len) *out_len = len;

    if (len >= buf_size) {
        free(json_str);
        return NOSTR_RELAY_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(buf, json_str, len + 1);
    free(json_str);

    return NOSTR_RELAY_OK;
}

nostr_relay_error_t nostr_event_serialize(const nostr_event* event, char* buf, size_t buf_size, size_t* out_len)
{
    if (!event || !buf || buf_size == 0) {
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    char* json_str = NULL;
    nostr_error_t err = nostr_event_to_json(event, &json_str);

    if (err != NOSTR_OK || !json_str) {
        return NOSTR_RELAY_ERR_MEMORY;
    }

    size_t len = strlen(json_str);
    if (out_len) *out_len = len;

    if (len >= buf_size) {
        free(json_str);
        return NOSTR_RELAY_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(buf, json_str, len + 1);
    free(json_str);

    return NOSTR_RELAY_OK;
}

#else

nostr_relay_error_t nostr_event_parse(const char* json, size_t json_len, nostr_event** event)
{
    (void)json;
    (void)json_len;
    (void)event;
    return NOSTR_RELAY_ERR_INVALID_JSON;
}

nostr_relay_error_t nostr_event_serialize_canonical(const nostr_event* event, char* buf, size_t buf_size, size_t* out_len)
{
    (void)event;
    (void)buf;
    (void)buf_size;
    (void)out_len;
    return NOSTR_RELAY_ERR_INVALID_JSON;
}

nostr_relay_error_t nostr_event_serialize(const nostr_event* event, char* buf, size_t buf_size, size_t* out_len)
{
    (void)event;
    (void)buf;
    (void)buf_size;
    (void)out_len;
    return NOSTR_RELAY_ERR_INVALID_JSON;
}

#endif

static int compare_event_ids(const uint8_t* a, const uint8_t* b)
{
    return memcmp(a, b, NOSTR_ID_SIZE);
}

int nostr_event_compare_replaceable(const nostr_event* a, const nostr_event* b)
{
    if (!a || !b) return 0;

    if (a->created_at < b->created_at) return -1;
    if (a->created_at > b->created_at) return 1;

    int id_cmp = compare_event_ids(a->id, b->id);
    if (id_cmp < 0) return 1;
    if (id_cmp > 0) return -1;
    return 0;
}

int nostr_event_compare_addressable(const nostr_event* a, const nostr_event* b)
{
    return nostr_event_compare_replaceable(a, b);
}

nostr_relay_error_t nostr_event_validate_full(const nostr_event* event, int64_t max_future_seconds, nostr_validation_result_t* result)
{
    if (!event || !result) {
        if (result) {
            result->valid = false;
            result->error_code = NOSTR_RELAY_ERR_MISSING_FIELD;
            strncpy(result->error_message, "null event", sizeof(result->error_message) - 1);
            result->error_field[0] = '\0';
        }
        return NOSTR_RELAY_ERR_MISSING_FIELD;
    }

    result->valid = false;
    result->error_code = NOSTR_RELAY_OK;
    result->error_message[0] = '\0';
    result->error_field[0] = '\0';

    if (!nostr_validate_timestamp(event->created_at, max_future_seconds)) {
        result->error_code = NOSTR_RELAY_ERR_FUTURE_EVENT;
        strncpy(result->error_message, "event creation date is too far off from the current time",
                sizeof(result->error_message) - 1);
        strncpy(result->error_field, "created_at", sizeof(result->error_field) - 1);
        return NOSTR_RELAY_ERR_FUTURE_EVENT;
    }

    if (nostr_event_is_expired_now(event)) {
        result->error_code = NOSTR_RELAY_ERR_EXPIRED_EVENT;
        strncpy(result->error_message, "event has expired", sizeof(result->error_message) - 1);
        strncpy(result->error_field, "expiration", sizeof(result->error_field) - 1);
        return NOSTR_RELAY_ERR_EXPIRED_EVENT;
    }

    nostr_event temp_event;
    memcpy(&temp_event, event, sizeof(nostr_event));

    nostr_error_t err = nostr_event_compute_id(&temp_event);
    if (err != NOSTR_OK) {
        result->error_code = NOSTR_RELAY_ERR_INVALID_ID;
        strncpy(result->error_message, "failed to compute event ID", sizeof(result->error_message) - 1);
        strncpy(result->error_field, "id", sizeof(result->error_field) - 1);
        return NOSTR_RELAY_ERR_INVALID_ID;
    }

    if (memcmp(event->id, temp_event.id, NOSTR_ID_SIZE) != 0) {
        result->error_code = NOSTR_RELAY_ERR_ID_MISMATCH;
        strncpy(result->error_message, "event ID does not match content", sizeof(result->error_message) - 1);
        strncpy(result->error_field, "id", sizeof(result->error_field) - 1);
        return NOSTR_RELAY_ERR_ID_MISMATCH;
    }

    err = nostr_event_verify(event);
    if (err != NOSTR_OK) {
        result->error_code = NOSTR_RELAY_ERR_SIG_MISMATCH;
        strncpy(result->error_message, "signature verification failed", sizeof(result->error_message) - 1);
        strncpy(result->error_field, "sig", sizeof(result->error_field) - 1);
        return NOSTR_RELAY_ERR_SIG_MISMATCH;
    }

    result->valid = true;
    return NOSTR_RELAY_OK;
}

void nostr_deletion_free(nostr_deletion_request_t* request)
{
    if (!request) return;

    if (request->event_ids) {
        for (size_t i = 0; i < request->event_ids_count; i++) {
            free(request->event_ids[i]);
        }
        free(request->event_ids);
    }

    if (request->addresses) {
        for (size_t i = 0; i < request->addresses_count; i++) {
            free(request->addresses[i]);
        }
        free(request->addresses);
    }

    free(request->reason);

    memset(request, 0, sizeof(nostr_deletion_request_t));
}

nostr_relay_error_t nostr_deletion_parse(const nostr_event* event, nostr_deletion_request_t* request)
{
    if (!event || !request) {
        return NOSTR_RELAY_ERR_MISSING_FIELD;
    }

    memset(request, 0, sizeof(nostr_deletion_request_t));

    if (event->kind != 5) {
        return NOSTR_RELAY_ERR_INVALID_KIND;
    }

    for (int i = 0; i < NOSTR_PUBKEY_SIZE; i++) {
        sprintf(request->pubkey + i * 2, "%02x", event->pubkey.data[i]);
    }
    request->pubkey[64] = '\0';

    if (event->content && event->content[0] != '\0') {
        request->reason = strdup(event->content);
        if (!request->reason) {
            nostr_deletion_free(request);
            return NOSTR_RELAY_ERR_MEMORY;
        }
    }

    size_t e_count = 0;
    size_t a_count = 0;

    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 && event->tags[i].values[0]) {
            if (strcmp(event->tags[i].values[0], "e") == 0) {
                e_count++;
            } else if (strcmp(event->tags[i].values[0], "a") == 0) {
                a_count++;
            }
        }
    }

    if (e_count > 0) {
        request->event_ids = calloc(e_count, sizeof(char*));
        if (!request->event_ids) {
            nostr_deletion_free(request);
            return NOSTR_RELAY_ERR_MEMORY;
        }
    }

    if (a_count > 0) {
        request->addresses = calloc(a_count, sizeof(char*));
        if (!request->addresses) {
            nostr_deletion_free(request);
            return NOSTR_RELAY_ERR_MEMORY;
        }
    }

    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 && event->tags[i].values[0] && event->tags[i].values[1]) {
            if (strcmp(event->tags[i].values[0], "e") == 0) {
                if (nostr_validate_hex64(event->tags[i].values[1])) {
                    request->event_ids[request->event_ids_count] = strdup(event->tags[i].values[1]);
                    if (!request->event_ids[request->event_ids_count]) {
                        nostr_deletion_free(request);
                        return NOSTR_RELAY_ERR_MEMORY;
                    }
                    request->event_ids_count++;
                }
            } else if (strcmp(event->tags[i].values[0], "a") == 0) {
                if (nostr_validate_address(event->tags[i].values[1])) {
                    request->addresses[request->addresses_count] = strdup(event->tags[i].values[1]);
                    if (!request->addresses[request->addresses_count]) {
                        nostr_deletion_free(request);
                        return NOSTR_RELAY_ERR_MEMORY;
                    }
                    request->addresses_count++;
                }
            }
        }
    }

    return NOSTR_RELAY_OK;
}

bool nostr_deletion_authorized(const nostr_deletion_request_t* request, const nostr_event* target_event)
{
    if (!request || !target_event) {
        return false;
    }

    char target_pubkey[65];
    nostr_bytes_to_hex(target_event->pubkey.data, NOSTR_PUBKEY_SIZE, target_pubkey);

    if (strcmp(request->pubkey, target_pubkey) != 0) {
        return false;
    }

    char target_id[65];
    nostr_bytes_to_hex(target_event->id, NOSTR_ID_SIZE, target_id);

    for (size_t i = 0; i < request->event_ids_count; i++) {
        if (strcmp(request->event_ids[i], target_id) == 0) {
            return true;
        }
    }

    return false;
}

bool nostr_deletion_authorized_address(const nostr_deletion_request_t* request, const nostr_event* target_event)
{
    if (!request || !target_event) {
        return false;
    }

    if (!nostr_kind_is_addressable(target_event->kind)) {
        return false;
    }

    char target_pubkey[65];
    nostr_bytes_to_hex(target_event->pubkey.data, NOSTR_PUBKEY_SIZE, target_pubkey);

    if (strcmp(request->pubkey, target_pubkey) != 0) {
        return false;
    }

    const char* d_tag = nostr_event_get_d_tag(target_event);
    if (!d_tag) {
        d_tag = "";
    }

    char target_address[256];
    int written = snprintf(target_address, sizeof(target_address), "%d:%s:%s",
                          target_event->kind, target_pubkey, d_tag);
    if (written < 0 || (size_t)written >= sizeof(target_address)) {
        return false;
    }

    for (size_t i = 0; i < request->addresses_count; i++) {
        if (strcmp(request->addresses[i], target_address) == 0) {
            return true;
        }
    }

    return false;
}

void nostr_tag_iterator_init(nostr_tag_iterator_t* iter, const nostr_event* event)
{
    if (!iter) return;

    iter->event = event;
    iter->current_index = 0;
}

const char** nostr_tag_iterator_next(nostr_tag_iterator_t* iter, size_t* tag_len)
{
    if (!iter || !iter->event || !iter->event->tags) {
        if (tag_len) *tag_len = 0;
        return NULL;
    }

    if (iter->current_index >= iter->event->tags_count) {
        if (tag_len) *tag_len = 0;
        return NULL;
    }

    size_t idx = iter->current_index++;
    if (tag_len) {
        *tag_len = iter->event->tags[idx].count;
    }
    return (const char**)iter->event->tags[idx].values;
}

bool nostr_tag_iterator_next_info(nostr_tag_iterator_t* iter, nostr_tag_info_t* tag)
{
    if (!iter || !tag) {
        return false;
    }

    size_t count = 0;
    const char** values = nostr_tag_iterator_next(iter, &count);

    if (!values || count == 0) {
        tag->name = NULL;
        tag->values = NULL;
        tag->values_count = 0;
        return false;
    }

    tag->name = values[0];
    if (count > 1) {
        tag->values = values + 1;
        tag->values_count = count - 1;
    } else {
        tag->values = NULL;
        tag->values_count = 0;
    }

    return true;
}

bool nostr_tag_is_indexable(const char* tag_name)
{
    if (!tag_name || tag_name[0] == '\0' || tag_name[1] != '\0') {
        return false;
    }

    char c = tag_name[0];
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

const uint8_t* nostr_event_get_id(const nostr_event* event)
{
    if (!event) return NULL;
    return event->id;
}

const uint8_t* nostr_event_get_pubkey(const nostr_event* event)
{
    if (!event) return NULL;
    return event->pubkey.data;
}

void nostr_event_get_id_hex(const nostr_event* event, char* out)
{
    if (!event || !out) return;
    for (int i = 0; i < NOSTR_ID_SIZE; i++) {
        sprintf(out + i * 2, "%02x", event->id[i]);
    }
    out[64] = '\0';
}

void nostr_event_get_pubkey_hex(const nostr_event* event, char* out)
{
    if (!event || !out) return;
    for (int i = 0; i < NOSTR_PUBKEY_SIZE; i++) {
        sprintf(out + i * 2, "%02x", event->pubkey.data[i]);
    }
    out[64] = '\0';
}

size_t nostr_event_get_tag_count(const nostr_event* event)
{
    if (!event) return 0;
    return event->tags_count;
}

const nostr_tag* nostr_event_get_tag(const nostr_event* event, size_t index)
{
    if (!event || !event->tags || index >= event->tags_count) {
        return NULL;
    }
    return &event->tags[index];
}

const char* nostr_tag_get_name(const nostr_tag* tag)
{
    if (!tag || tag->count == 0 || !tag->values) {
        return NULL;
    }
    return tag->values[0];
}

size_t nostr_tag_get_value_count(const nostr_tag* tag)
{
    if (!tag) return 0;
    return tag->count;
}

const char* nostr_tag_get_value(const nostr_tag* tag, size_t index)
{
    if (!tag || !tag->values || index >= tag->count) {
        return NULL;
    }
    return tag->values[index];
}

const nostr_tag* nostr_event_find_tag(const nostr_event* event, const char* tag_name)
{
    if (!event || !tag_name || !event->tags) {
        return NULL;
    }

    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 1 &&
            event->tags[i].values[0] &&
            strcmp(event->tags[i].values[0], tag_name) == 0) {
            return &event->tags[i];
        }
    }
    return NULL;
}

bool nostr_event_is_deletion(const nostr_event* event)
{
    if (!event) return false;
    return event->kind == 5;
}

static nostr_relay_error_t hex_string_to_bytes(const char* hex, uint8_t* out, size_t out_size)
{
    if (!hex || !out) return NOSTR_RELAY_ERR_INVALID_ID;

    size_t hex_len = strlen(hex);
    if (hex_len != out_size * 2) return NOSTR_RELAY_ERR_INVALID_ID;

    for (size_t i = 0; i < out_size; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            return NOSTR_RELAY_ERR_INVALID_ID;
        }
        out[i] = (uint8_t)byte;
    }
    return NOSTR_RELAY_OK;
}

uint8_t (*nostr_event_get_e_tags_binary(const nostr_event* event, size_t* out_count))[32]
{
    if (!event || !out_count) {
        if (out_count) *out_count = 0;
        return NULL;
    }

    size_t count = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 &&
            event->tags[i].values[0] &&
            strcmp(event->tags[i].values[0], "e") == 0 &&
            event->tags[i].values[1] &&
            nostr_validate_hex64(event->tags[i].values[1])) {
            count++;
        }
    }

    if (count == 0) {
        *out_count = 0;
        return NULL;
    }

    uint8_t (*result)[32] = malloc(count * 32);
    if (!result) {
        *out_count = 0;
        return NULL;
    }

    size_t idx = 0;
    for (size_t i = 0; i < event->tags_count && idx < count; i++) {
        if (event->tags[i].count >= 2 &&
            event->tags[i].values[0] &&
            strcmp(event->tags[i].values[0], "e") == 0 &&
            event->tags[i].values[1] &&
            nostr_validate_hex64(event->tags[i].values[1])) {
            if (hex_string_to_bytes(event->tags[i].values[1], result[idx], 32) == NOSTR_RELAY_OK) {
                idx++;
            }
        }
    }

    *out_count = idx;
    return result;
}

uint8_t (*nostr_event_get_p_tags_binary(const nostr_event* event, size_t* out_count))[32]
{
    if (!event || !out_count) {
        if (out_count) *out_count = 0;
        return NULL;
    }

    size_t count = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 &&
            event->tags[i].values[0] &&
            strcmp(event->tags[i].values[0], "p") == 0 &&
            event->tags[i].values[1] &&
            nostr_validate_hex64(event->tags[i].values[1])) {
            count++;
        }
    }

    if (count == 0) {
        *out_count = 0;
        return NULL;
    }

    uint8_t (*result)[32] = malloc(count * 32);
    if (!result) {
        *out_count = 0;
        return NULL;
    }

    size_t idx = 0;
    for (size_t i = 0; i < event->tags_count && idx < count; i++) {
        if (event->tags[i].count >= 2 &&
            event->tags[i].values[0] &&
            strcmp(event->tags[i].values[0], "p") == 0 &&
            event->tags[i].values[1] &&
            nostr_validate_hex64(event->tags[i].values[1])) {
            if (hex_string_to_bytes(event->tags[i].values[1], result[idx], 32) == NOSTR_RELAY_OK) {
                idx++;
            }
        }
    }

    *out_count = idx;
    return result;
}

nostr_relay_error_t nostr_hex_to_bytes(const char* hex, size_t hex_len, uint8_t* out, size_t out_size)
{
    if (!hex || !out) {
        return NOSTR_RELAY_ERR_INVALID_ID;
    }

    if (hex_len % 2 != 0) {
        return NOSTR_RELAY_ERR_INVALID_ID;
    }

    size_t bytes_needed = hex_len / 2;
    if (bytes_needed > out_size) {
        return NOSTR_RELAY_ERR_BUFFER_TOO_SMALL;
    }

    for (size_t i = 0; i < bytes_needed; i++) {
        char c1 = hex[i * 2];
        char c2 = hex[i * 2 + 1];

        unsigned int val1, val2;

        if (c1 >= '0' && c1 <= '9') val1 = c1 - '0';
        else if (c1 >= 'a' && c1 <= 'f') val1 = c1 - 'a' + 10;
        else if (c1 >= 'A' && c1 <= 'F') val1 = c1 - 'A' + 10;
        else return NOSTR_RELAY_ERR_INVALID_ID;

        if (c2 >= '0' && c2 <= '9') val2 = c2 - '0';
        else if (c2 >= 'a' && c2 <= 'f') val2 = c2 - 'a' + 10;
        else if (c2 >= 'A' && c2 <= 'F') val2 = c2 - 'A' + 10;
        else return NOSTR_RELAY_ERR_INVALID_ID;

        out[i] = (uint8_t)((val1 << 4) | val2);
    }

    return NOSTR_RELAY_OK;
}

void nostr_bytes_to_hex(const uint8_t* bytes, size_t bytes_len, char* out)
{
    if (!bytes || !out) return;

    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < bytes_len; i++) {
        out[i * 2] = hex_chars[(bytes[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex_chars[bytes[i] & 0x0f];
    }
    out[bytes_len * 2] = '\0';
}

void nostr_free(void* ptr)
{
    free(ptr);
}

void nostr_free_strings(char** strings, size_t count)
{
    if (!strings) return;

    for (size_t i = 0; i < count; i++) {
        free(strings[i]);
    }
    free(strings);
}

const char* nostr_version(void)
{
    return "0.1.1";
}
