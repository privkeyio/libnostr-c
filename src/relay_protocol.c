/**
 * @file relay_protocol.c
 * @brief NIP-01 Relay-side protocol implementation
 */

#include "../include/nostr_relay_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>

#ifdef NOSTR_FEATURE_JSON_ENHANCED
#include <cjson/cJSON.h>
#endif

/* ============================================================================
 * Error Handling
 * ============================================================================ */

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
    if (result->error_code == NOSTR_RELAY_ERR_ID_MISMATCH) {
        prefix = "invalid:";
    } else if (result->error_code == NOSTR_RELAY_ERR_SIG_MISMATCH) {
        prefix = "invalid:";
    } else if (result->error_code == NOSTR_RELAY_ERR_FUTURE_EVENT) {
        prefix = "invalid:";
    } else if (result->error_code == NOSTR_RELAY_ERR_EXPIRED_EVENT) {
        prefix = "invalid:";
    }

    int len;
    if (result->error_field[0] != '\0') {
        len = snprintf(buf, buf_size, "%s %s for field '%s'",
                      prefix, result->error_message, result->error_field);
    } else {
        len = snprintf(buf, buf_size, "%s %s", prefix, result->error_message);
    }

    return (len > 0 && (size_t)len < buf_size) ? (size_t)len : 0;
}

/* ============================================================================
 * Validation Utilities
 * ============================================================================ */

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

int64_t nostr_timestamp_now(void)
{
    return (int64_t)time(NULL);
}

/* ============================================================================
 * Event Kind Classification (NIP-01)
 * ============================================================================ */

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

/* ============================================================================
 * Tag Utilities
 * ============================================================================ */

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

/* ============================================================================
 * Expiration (NIP-40)
 * ============================================================================ */

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

/* ============================================================================
 * Event Parsing and Serialization (NIP-01)
 * ============================================================================ */

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

static char* escape_json_string_canonical(const char* input)
{
    if (!input) return NULL;

    size_t len = strlen(input);
    size_t max_output_len = len * 2 + 1;
    char* output = malloc(max_output_len);
    if (!output) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)input[i];
        switch (c) {
            case '"':
                output[j++] = '\\';
                output[j++] = '"';
                break;
            case '\\':
                output[j++] = '\\';
                output[j++] = '\\';
                break;
            case '\n':
                output[j++] = '\\';
                output[j++] = 'n';
                break;
            case '\r':
                output[j++] = '\\';
                output[j++] = 'r';
                break;
            case '\t':
                output[j++] = '\\';
                output[j++] = 't';
                break;
            case '\b':
                output[j++] = '\\';
                output[j++] = 'b';
                break;
            case '\f':
                output[j++] = '\\';
                output[j++] = 'f';
                break;
            default:
                output[j++] = (char)c;
                break;
        }
    }
    output[j] = '\0';
    return output;
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

    char* content_escaped = escape_json_string_canonical(event->content ? event->content : "");
    if (!content_escaped) {
        return NOSTR_RELAY_ERR_MEMORY;
    }

    cJSON* serialization = cJSON_CreateArray();
    if (!serialization) {
        free(content_escaped);
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
    free(content_escaped);

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

#else  /* !NOSTR_FEATURE_JSON_ENHANCED */

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

#endif  /* NOSTR_FEATURE_JSON_ENHANCED */

/* ============================================================================
 * Event Comparison Functions
 * ============================================================================ */

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

/* ============================================================================
 * Event Validation (NIP-01)
 * ============================================================================ */

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

/* ============================================================================
 * Filter Functions (NIP-01)
 * ============================================================================ */

#ifdef NOSTR_FEATURE_JSON_ENHANCED

static nostr_relay_error_t parse_string_array(cJSON* arr, char*** out_arr, size_t* out_count)
{
    if (!arr || !cJSON_IsArray(arr)) {
        *out_arr = NULL;
        *out_count = 0;
        return NOSTR_RELAY_OK;
    }

    int count = cJSON_GetArraySize(arr);
    if (count == 0) {
        *out_arr = NULL;
        *out_count = 0;
        return NOSTR_RELAY_OK;
    }

    *out_arr = malloc(sizeof(char*) * count);
    if (!*out_arr) {
        return NOSTR_RELAY_ERR_MEMORY;
    }

    *out_count = 0;
    for (int i = 0; i < count; i++) {
        cJSON* item = cJSON_GetArrayItem(arr, i);
        if (cJSON_IsString(item) && item->valuestring) {
            (*out_arr)[*out_count] = strdup(item->valuestring);
            if (!(*out_arr)[*out_count]) {
                for (size_t j = 0; j < *out_count; j++) {
                    free((*out_arr)[j]);
                }
                free(*out_arr);
                *out_arr = NULL;
                *out_count = 0;
                return NOSTR_RELAY_ERR_MEMORY;
            }
            (*out_count)++;
        }
    }

    return NOSTR_RELAY_OK;
}

static nostr_relay_error_t parse_int_array(cJSON* arr, int32_t** out_arr, size_t* out_count)
{
    if (!arr || !cJSON_IsArray(arr)) {
        *out_arr = NULL;
        *out_count = 0;
        return NOSTR_RELAY_OK;
    }

    int count = cJSON_GetArraySize(arr);
    if (count == 0) {
        *out_arr = NULL;
        *out_count = 0;
        return NOSTR_RELAY_OK;
    }

    *out_arr = malloc(sizeof(int32_t) * count);
    if (!*out_arr) {
        return NOSTR_RELAY_ERR_MEMORY;
    }

    *out_count = 0;
    for (int i = 0; i < count; i++) {
        cJSON* item = cJSON_GetArrayItem(arr, i);
        if (cJSON_IsNumber(item)) {
            (*out_arr)[(*out_count)++] = (int32_t)item->valueint;
        }
    }

    return NOSTR_RELAY_OK;
}

nostr_relay_error_t nostr_filter_parse(const char* json, size_t json_len, nostr_filter_t* filter)
{
    (void)json_len;

    if (!json || !filter) {
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    memset(filter, 0, sizeof(nostr_filter_t));

    cJSON* root = cJSON_Parse(json);
    if (!root) {
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    nostr_relay_error_t err;

    err = parse_string_array(cJSON_GetObjectItem(root, "ids"), &filter->ids, &filter->ids_count);
    if (err != NOSTR_RELAY_OK) goto cleanup;

    err = parse_string_array(cJSON_GetObjectItem(root, "authors"), &filter->authors, &filter->authors_count);
    if (err != NOSTR_RELAY_OK) goto cleanup;

    err = parse_int_array(cJSON_GetObjectItem(root, "kinds"), &filter->kinds, &filter->kinds_count);
    if (err != NOSTR_RELAY_OK) goto cleanup;

    err = parse_string_array(cJSON_GetObjectItem(root, "#e"), &filter->e_tags, &filter->e_tags_count);
    if (err != NOSTR_RELAY_OK) goto cleanup;

    err = parse_string_array(cJSON_GetObjectItem(root, "#p"), &filter->p_tags, &filter->p_tags_count);
    if (err != NOSTR_RELAY_OK) goto cleanup;

    size_t generic_count = 0;
    nostr_generic_tag_filter_t* generic_tags = NULL;

    cJSON* item;
    cJSON_ArrayForEach(item, root) {
        if (item->string && item->string[0] == '#' &&
            item->string[1] != '\0' && item->string[2] == '\0') {
            char tag_char = item->string[1];
            if (tag_char != 'e' && tag_char != 'p' && isalpha((unsigned char)tag_char)) {
                generic_count++;
            }
        }
    }

    if (generic_count > 0) {
        generic_tags = calloc(generic_count, sizeof(nostr_generic_tag_filter_t));
        if (!generic_tags) {
            err = NOSTR_RELAY_ERR_MEMORY;
            goto cleanup;
        }

        size_t idx = 0;
        cJSON_ArrayForEach(item, root) {
            if (item->string && item->string[0] == '#' &&
                item->string[1] != '\0' && item->string[2] == '\0') {
                char tag_char = item->string[1];
                if (tag_char != 'e' && tag_char != 'p' && isalpha((unsigned char)tag_char)) {
                    generic_tags[idx].tag_name = tag_char;
                    err = parse_string_array(item, &generic_tags[idx].values, &generic_tags[idx].values_count);
                    if (err != NOSTR_RELAY_OK) {
                        filter->generic_tags = generic_tags;
                        filter->generic_tags_count = idx;
                        goto cleanup;
                    }
                    idx++;
                }
            }
        }
        filter->generic_tags = generic_tags;
        filter->generic_tags_count = generic_count;
    }

    cJSON* since = cJSON_GetObjectItem(root, "since");
    if (since && cJSON_IsNumber(since)) {
        filter->since = (int64_t)since->valuedouble;
    }

    cJSON* until = cJSON_GetObjectItem(root, "until");
    if (until && cJSON_IsNumber(until)) {
        filter->until = (int64_t)until->valuedouble;
    }

    cJSON* limit = cJSON_GetObjectItem(root, "limit");
    if (limit && cJSON_IsNumber(limit)) {
        filter->limit = limit->valueint;
    }

    cJSON_Delete(root);
    return NOSTR_RELAY_OK;

cleanup:
    cJSON_Delete(root);
    nostr_filter_free(filter);
    return err;
}

#else

nostr_relay_error_t nostr_filter_parse(const char* json, size_t json_len, nostr_filter_t* filter)
{
    (void)json;
    (void)json_len;
    (void)filter;
    return NOSTR_RELAY_ERR_INVALID_JSON;
}

#endif

void nostr_filter_free(nostr_filter_t* filter)
{
    if (!filter) return;

    if (filter->ids) {
        for (size_t i = 0; i < filter->ids_count; i++) {
            free(filter->ids[i]);
        }
        free(filter->ids);
    }

    if (filter->authors) {
        for (size_t i = 0; i < filter->authors_count; i++) {
            free(filter->authors[i]);
        }
        free(filter->authors);
    }

    free(filter->kinds);

    if (filter->e_tags) {
        for (size_t i = 0; i < filter->e_tags_count; i++) {
            free(filter->e_tags[i]);
        }
        free(filter->e_tags);
    }

    if (filter->p_tags) {
        for (size_t i = 0; i < filter->p_tags_count; i++) {
            free(filter->p_tags[i]);
        }
        free(filter->p_tags);
    }

    if (filter->generic_tags) {
        for (size_t i = 0; i < filter->generic_tags_count; i++) {
            if (filter->generic_tags[i].values) {
                for (size_t j = 0; j < filter->generic_tags[i].values_count; j++) {
                    free(filter->generic_tags[i].values[j]);
                }
                free(filter->generic_tags[i].values);
            }
        }
        free(filter->generic_tags);
    }

    memset(filter, 0, sizeof(nostr_filter_t));
}

nostr_relay_error_t nostr_filter_validate(const nostr_filter_t* filter, nostr_validation_result_t* result)
{
    if (!filter || !result) {
        if (result) {
            result->valid = false;
            result->error_code = NOSTR_RELAY_ERR_MISSING_FIELD;
        }
        return NOSTR_RELAY_ERR_MISSING_FIELD;
    }

    result->valid = true;
    result->error_code = NOSTR_RELAY_OK;
    result->error_message[0] = '\0';
    result->error_field[0] = '\0';

    for (size_t i = 0; i < filter->ids_count; i++) {
        if (!nostr_validate_hex_prefix(filter->ids[i])) {
            result->valid = false;
            result->error_code = NOSTR_RELAY_ERR_INVALID_ID;
            strncpy(result->error_message, "invalid hex prefix in ids", sizeof(result->error_message) - 1);
            strncpy(result->error_field, "ids", sizeof(result->error_field) - 1);
            return NOSTR_RELAY_ERR_INVALID_ID;
        }
    }

    for (size_t i = 0; i < filter->authors_count; i++) {
        if (!nostr_validate_hex_prefix(filter->authors[i])) {
            result->valid = false;
            result->error_code = NOSTR_RELAY_ERR_INVALID_PUBKEY;
            strncpy(result->error_message, "invalid hex prefix in authors", sizeof(result->error_message) - 1);
            strncpy(result->error_field, "authors", sizeof(result->error_field) - 1);
            return NOSTR_RELAY_ERR_INVALID_PUBKEY;
        }
    }

    for (size_t i = 0; i < filter->e_tags_count; i++) {
        if (!nostr_validate_hex64(filter->e_tags[i])) {
            result->valid = false;
            result->error_code = NOSTR_RELAY_ERR_INVALID_ID;
            strncpy(result->error_message, "invalid event ID in #e filter", sizeof(result->error_message) - 1);
            strncpy(result->error_field, "#e", sizeof(result->error_field) - 1);
            return NOSTR_RELAY_ERR_INVALID_ID;
        }
    }

    for (size_t i = 0; i < filter->p_tags_count; i++) {
        if (!nostr_validate_hex64(filter->p_tags[i])) {
            result->valid = false;
            result->error_code = NOSTR_RELAY_ERR_INVALID_PUBKEY;
            strncpy(result->error_message, "invalid pubkey in #p filter", sizeof(result->error_message) - 1);
            strncpy(result->error_field, "#p", sizeof(result->error_field) - 1);
            return NOSTR_RELAY_ERR_INVALID_PUBKEY;
        }
    }

    return NOSTR_RELAY_OK;
}

static bool hex_starts_with(const char* hex, size_t hex_len, const char* prefix)
{
    size_t prefix_len = strlen(prefix);
    if (prefix_len > hex_len) return false;
    return strncmp(hex, prefix, prefix_len) == 0;
}

static void id_to_hex(const uint8_t* id, char* hex)
{
    for (int i = 0; i < NOSTR_ID_SIZE; i++) {
        sprintf(hex + i * 2, "%02x", id[i]);
    }
    hex[64] = '\0';
}

static void pubkey_to_hex(const nostr_key* key, char* hex)
{
    for (int i = 0; i < NOSTR_PUBKEY_SIZE; i++) {
        sprintf(hex + i * 2, "%02x", key->data[i]);
    }
    hex[64] = '\0';
}

bool nostr_filter_matches(const nostr_filter_t* filter, const nostr_event* event)
{
    if (!filter || !event) return false;

    char hex_buf[65];

    if (filter->ids_count > 0) {
        id_to_hex(event->id, hex_buf);
        bool matched = false;
        for (size_t i = 0; i < filter->ids_count; i++) {
            if (hex_starts_with(hex_buf, 64, filter->ids[i])) {
                matched = true;
                break;
            }
        }
        if (!matched) return false;
    }

    if (filter->authors_count > 0) {
        pubkey_to_hex(&event->pubkey, hex_buf);
        bool matched = false;
        for (size_t i = 0; i < filter->authors_count; i++) {
            if (hex_starts_with(hex_buf, 64, filter->authors[i])) {
                matched = true;
                break;
            }
        }
        if (!matched) return false;
    }

    if (filter->kinds_count > 0) {
        bool matched = false;
        for (size_t i = 0; i < filter->kinds_count; i++) {
            if (filter->kinds[i] == (int32_t)event->kind) {
                matched = true;
                break;
            }
        }
        if (!matched) return false;
    }

    if (filter->since > 0 && event->created_at < filter->since) {
        return false;
    }

    if (filter->until > 0 && event->created_at > filter->until) {
        return false;
    }

    if (filter->e_tags_count > 0) {
        bool matched = false;
        const char* e_values[256];
        size_t e_count = nostr_event_get_tag_values(event, "e", e_values, 256);

        for (size_t i = 0; i < filter->e_tags_count && !matched; i++) {
            for (size_t j = 0; j < e_count; j++) {
                if (e_values[j] && strcmp(e_values[j], filter->e_tags[i]) == 0) {
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) return false;
    }

    if (filter->p_tags_count > 0) {
        bool matched = false;
        const char* p_values[256];
        size_t p_count = nostr_event_get_tag_values(event, "p", p_values, 256);

        for (size_t i = 0; i < filter->p_tags_count && !matched; i++) {
            for (size_t j = 0; j < p_count; j++) {
                if (p_values[j] && strcmp(p_values[j], filter->p_tags[i]) == 0) {
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) return false;
    }

    for (size_t t = 0; t < filter->generic_tags_count; t++) {
        char tag_name[2] = { filter->generic_tags[t].tag_name, '\0' };

        const char* tag_values[256];
        size_t tag_count = nostr_event_get_tag_values(event, tag_name, tag_values, 256);

        bool matched = false;
        for (size_t i = 0; i < filter->generic_tags[t].values_count && !matched; i++) {
            for (size_t j = 0; j < tag_count; j++) {
                if (tag_values[j] && strcmp(tag_values[j], filter->generic_tags[t].values[i]) == 0) {
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) return false;
    }

    return true;
}

bool nostr_filters_match(const nostr_filter_t* filters, size_t count, const nostr_event* event)
{
    if (!filters || count == 0 || !event) return false;

    for (size_t i = 0; i < count; i++) {
        if (nostr_filter_matches(&filters[i], event)) {
            return true;
        }
    }
    return false;
}

/* ============================================================================
 * Client Message Parsing (NIP-01)
 * ============================================================================ */

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

/* ============================================================================
 * Relay Message Serialization (NIP-01)
 * ============================================================================ */

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

            if (msg->data.event.event) {
                char* event_json = NULL;
                if (nostr_event_to_json(msg->data.event.event, &event_json) == NOSTR_OK && event_json) {
                    cJSON* event_obj = cJSON_Parse(event_json);
                    free(event_json);
                    if (event_obj) {
                        cJSON_AddItemToArray(root, event_obj);
                    }
                }
            }
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
