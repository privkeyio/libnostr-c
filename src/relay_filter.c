/**
 * @file relay_filter.c
 * @brief NIP-01 Filter parsing, matching, and accessor functions
 */

#include "../include/nostr_relay_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#ifdef NOSTR_FEATURE_JSON_ENHANCED
#include <cjson/cJSON.h>
#endif

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

    if (count > NOSTR_MAX_TAG_FILTER_VALUES) {
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    *out_arr = calloc((size_t)count, sizeof(char*));
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

    if (count > NOSTR_MAX_TAG_FILTER_VALUES) {
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    *out_arr = calloc((size_t)count, sizeof(int32_t));
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
    if (!json || !filter) {
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    memset(filter, 0, sizeof(nostr_filter_t));

    cJSON* root = (json_len > 0) ? cJSON_ParseWithLength(json, json_len) : cJSON_Parse(json);
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

bool nostr_filter_matches(const nostr_filter_t* filter, const nostr_event* event)
{
    if (!filter || !event) return false;

    char hex_buf[65];

    if (filter->ids_count > 0) {
        nostr_bytes_to_hex(event->id, NOSTR_ID_SIZE, hex_buf);
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
        nostr_bytes_to_hex(event->pubkey.data, NOSTR_PUBKEY_SIZE, hex_buf);
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
        const char* e_values[NOSTR_MAX_TAG_FILTER_VALUES];
        size_t e_count = nostr_event_get_tag_values(event, "e", e_values, NOSTR_MAX_TAG_FILTER_VALUES);

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
        const char* p_values[NOSTR_MAX_TAG_FILTER_VALUES];
        size_t p_count = nostr_event_get_tag_values(event, "p", p_values, NOSTR_MAX_TAG_FILTER_VALUES);

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

        const char* tag_values[NOSTR_MAX_TAG_FILTER_VALUES];
        size_t tag_count = nostr_event_get_tag_values(event, tag_name, tag_values, NOSTR_MAX_TAG_FILTER_VALUES);

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

const char** nostr_filter_get_e_tags(const nostr_filter_t* filter, size_t* count)
{
    if (!filter) {
        if (count) *count = 0;
        return NULL;
    }

    if (count) *count = filter->e_tags_count;
    return (const char**)filter->e_tags;
}

const char** nostr_filter_get_p_tags(const nostr_filter_t* filter, size_t* count)
{
    if (!filter) {
        if (count) *count = 0;
        return NULL;
    }

    if (count) *count = filter->p_tags_count;
    return (const char**)filter->p_tags;
}

const char** nostr_filter_get_tag_values(const nostr_filter_t* filter, char tag_name, size_t* count)
{
    if (!filter) {
        if (count) *count = 0;
        return NULL;
    }

    if (tag_name == 'e') {
        return nostr_filter_get_e_tags(filter, count);
    }
    if (tag_name == 'p') {
        return nostr_filter_get_p_tags(filter, count);
    }

    for (size_t i = 0; i < filter->generic_tags_count; i++) {
        if (filter->generic_tags[i].tag_name == tag_name) {
            if (count) *count = filter->generic_tags[i].values_count;
            return (const char**)filter->generic_tags[i].values;
        }
    }

    if (count) *count = 0;
    return NULL;
}

bool nostr_filter_has_tag_filters(const nostr_filter_t* filter)
{
    if (!filter) return false;

    return (filter->e_tags_count > 0 ||
            filter->p_tags_count > 0 ||
            filter->generic_tags_count > 0);
}

const char** nostr_filter_get_ids(const nostr_filter_t* filter, size_t* out_count)
{
    if (!filter) {
        if (out_count) *out_count = 0;
        return NULL;
    }
    if (out_count) *out_count = filter->ids_count;
    return (const char**)filter->ids;
}

const char** nostr_filter_get_authors(const nostr_filter_t* filter, size_t* out_count)
{
    if (!filter) {
        if (out_count) *out_count = 0;
        return NULL;
    }
    if (out_count) *out_count = filter->authors_count;
    return (const char**)filter->authors;
}

const int32_t* nostr_filter_get_kinds(const nostr_filter_t* filter, size_t* out_count)
{
    if (!filter) {
        if (out_count) *out_count = 0;
        return NULL;
    }
    if (out_count) *out_count = filter->kinds_count;
    return filter->kinds;
}

int64_t nostr_filter_get_since(const nostr_filter_t* filter)
{
    if (!filter) return 0;
    return filter->since;
}

int64_t nostr_filter_get_until(const nostr_filter_t* filter)
{
    if (!filter) return 0;
    return filter->until;
}

int32_t nostr_filter_get_limit(const nostr_filter_t* filter)
{
    if (!filter) return 0;
    return filter->limit;
}

static nostr_relay_error_t clone_string_array(char*** dst, size_t* dst_count,
                                               char** src, size_t src_count)
{
    if (src_count == 0 || !src) {
        *dst = NULL;
        *dst_count = 0;
        return NOSTR_RELAY_OK;
    }

    *dst = calloc(src_count, sizeof(char*));
    if (!*dst) {
        *dst_count = 0;
        return NOSTR_RELAY_ERR_MEMORY;
    }

    for (size_t i = 0; i < src_count; i++) {
        if (src[i]) {
            (*dst)[i] = strdup(src[i]);
            if (!(*dst)[i]) {
                for (size_t j = 0; j < i; j++) {
                    free((*dst)[j]);
                }
                free(*dst);
                *dst = NULL;
                *dst_count = 0;
                return NOSTR_RELAY_ERR_MEMORY;
            }
        }
    }

    *dst_count = src_count;
    return NOSTR_RELAY_OK;
}

nostr_relay_error_t nostr_filter_clone(nostr_filter_t* dst, const nostr_filter_t* src)
{
    if (!dst || !src) {
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    memset(dst, 0, sizeof(nostr_filter_t));

    nostr_relay_error_t err;

    err = clone_string_array(&dst->ids, &dst->ids_count, src->ids, src->ids_count);
    if (err != NOSTR_RELAY_OK) goto cleanup;

    err = clone_string_array(&dst->authors, &dst->authors_count, src->authors, src->authors_count);
    if (err != NOSTR_RELAY_OK) goto cleanup;

    if (src->kinds_count > 0 && src->kinds) {
        dst->kinds = calloc(src->kinds_count, sizeof(int32_t));
        if (!dst->kinds) {
            err = NOSTR_RELAY_ERR_MEMORY;
            goto cleanup;
        }
        memcpy(dst->kinds, src->kinds, src->kinds_count * sizeof(int32_t));
        dst->kinds_count = src->kinds_count;
    }

    err = clone_string_array(&dst->e_tags, &dst->e_tags_count, src->e_tags, src->e_tags_count);
    if (err != NOSTR_RELAY_OK) goto cleanup;

    err = clone_string_array(&dst->p_tags, &dst->p_tags_count, src->p_tags, src->p_tags_count);
    if (err != NOSTR_RELAY_OK) goto cleanup;

    if (src->generic_tags_count > 0 && src->generic_tags) {
        dst->generic_tags = calloc(src->generic_tags_count, sizeof(nostr_generic_tag_filter_t));
        if (!dst->generic_tags) {
            err = NOSTR_RELAY_ERR_MEMORY;
            goto cleanup;
        }

        for (size_t i = 0; i < src->generic_tags_count; i++) {
            dst->generic_tags[i].tag_name = src->generic_tags[i].tag_name;
            err = clone_string_array(&dst->generic_tags[i].values,
                                     &dst->generic_tags[i].values_count,
                                     src->generic_tags[i].values,
                                     src->generic_tags[i].values_count);
            if (err != NOSTR_RELAY_OK) {
                dst->generic_tags_count = i;
                goto cleanup;
            }
        }
        dst->generic_tags_count = src->generic_tags_count;
    }

    dst->since = src->since;
    dst->until = src->until;
    dst->limit = src->limit;

    return NOSTR_RELAY_OK;

cleanup:
    nostr_filter_free(dst);
    return err;
}
