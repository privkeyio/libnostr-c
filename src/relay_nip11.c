/**
 * @file relay_nip11.c
 * @brief NIP-11 Relay Information Document
 */

#include "../include/nostr_relay_protocol.h"
#include <stdlib.h>
#include <string.h>

#ifdef NOSTR_FEATURE_JSON_ENHANCED
#include <cjson/cJSON.h>
#endif

void nostr_relay_limitation_init(nostr_relay_limitation_t* limitation)
{
    if (!limitation) return;

    memset(limitation, 0, sizeof(nostr_relay_limitation_t));
    limitation->max_message_length = NOSTR_DEFAULT_MAX_MESSAGE_LENGTH;
    limitation->max_subscriptions = NOSTR_DEFAULT_MAX_SUBSCRIPTIONS;
    limitation->max_filters = NOSTR_DEFAULT_MAX_FILTERS;
    limitation->max_limit = NOSTR_DEFAULT_MAX_LIMIT;
    limitation->max_subid_length = NOSTR_DEFAULT_MAX_SUBID_LENGTH;
    limitation->max_event_tags = NOSTR_DEFAULT_MAX_EVENT_TAGS;
    limitation->max_content_length = NOSTR_DEFAULT_MAX_CONTENT_LENGTH;
    limitation->default_limit = NOSTR_DEFAULT_DEFAULT_LIMIT;
    limitation->min_pow_difficulty = 0;
    limitation->auth_required = false;
    limitation->payment_required = false;
    limitation->restricted_writes = false;
    limitation->created_at_lower_limit = 0;
    limitation->created_at_upper_limit = 0;
}

void nostr_relay_info_init(nostr_relay_info_t* info)
{
    if (!info) return;

    memset(info, 0, sizeof(nostr_relay_info_t));
    nostr_relay_limitation_init(&info->limitation);
}

nostr_relay_error_t nostr_relay_info_set_nips(nostr_relay_info_t* info, const int32_t* nips, size_t count)
{
    if (!info) {
        return NOSTR_RELAY_ERR_MISSING_FIELD;
    }

    free(info->supported_nips);
    info->supported_nips = NULL;
    info->supported_nips_count = 0;

    if (count == 0 || !nips) {
        return NOSTR_RELAY_OK;
    }

    int32_t* copy = malloc(count * sizeof(int32_t));
    if (!copy) {
        return NOSTR_RELAY_ERR_MEMORY;
    }

    memcpy(copy, nips, count * sizeof(int32_t));
    info->supported_nips = copy;
    info->supported_nips_count = count;
    return NOSTR_RELAY_OK;
}

nostr_relay_error_t nostr_relay_info_add_nip(nostr_relay_info_t* info, int32_t nip)
{
    if (!info) {
        return NOSTR_RELAY_ERR_MISSING_FIELD;
    }

    size_t new_count = info->supported_nips_count + 1;
    int32_t* new_nips = realloc(info->supported_nips, new_count * sizeof(int32_t));
    if (!new_nips) {
        return NOSTR_RELAY_ERR_MEMORY;
    }

    new_nips[info->supported_nips_count] = nip;
    info->supported_nips = new_nips;
    info->supported_nips_count = new_count;
    return NOSTR_RELAY_OK;
}

void nostr_relay_info_free(nostr_relay_info_t* info)
{
    if (!info) return;

    if (info->retention) {
        for (size_t i = 0; i < info->retention_count; i++) {
            if (info->retention[i].kinds) {
                free((void*)info->retention[i].kinds);
            }
        }
        free((void*)info->retention);
    }

    if (info->fees.admission) {
        for (size_t i = 0; i < info->fees.admission_count; i++) {
            if (info->fees.admission[i].unit) {
                free((void*)info->fees.admission[i].unit);
            }
        }
        free((void*)info->fees.admission);
    }

    if (info->fees.subscription) {
        for (size_t i = 0; i < info->fees.subscription_count; i++) {
            if (info->fees.subscription[i].unit) {
                free((void*)info->fees.subscription[i].unit);
            }
        }
        free((void*)info->fees.subscription);
    }

    if (info->fees.publication) {
        for (size_t i = 0; i < info->fees.publication_count; i++) {
            if (info->fees.publication[i].kinds) {
                free((void*)info->fees.publication[i].kinds);
            }
            if (info->fees.publication[i].unit) {
                free((void*)info->fees.publication[i].unit);
            }
        }
        free((void*)info->fees.publication);
    }

    free(info->supported_nips);
    free((void*)info->relay_countries);
    free((void*)info->language_tags);
    free((void*)info->tags);

    memset(info, 0, sizeof(nostr_relay_info_t));
}

#ifdef NOSTR_FEATURE_JSON_ENHANCED

nostr_relay_error_t nostr_relay_limitation_serialize(const nostr_relay_limitation_t* limitation,
                                                     char* buf, size_t buf_size, size_t* out_len)
{
    if (!limitation || !buf || buf_size == 0) {
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    cJSON* obj = cJSON_CreateObject();
    if (!obj) {
        return NOSTR_RELAY_ERR_MEMORY;
    }

    if (limitation->max_message_length > 0) {
        cJSON_AddNumberToObject(obj, "max_message_length", limitation->max_message_length);
    }
    if (limitation->max_subscriptions > 0) {
        cJSON_AddNumberToObject(obj, "max_subscriptions", limitation->max_subscriptions);
    }
    if (limitation->max_filters > 0) {
        cJSON_AddNumberToObject(obj, "max_filters", limitation->max_filters);
    }
    if (limitation->max_limit > 0) {
        cJSON_AddNumberToObject(obj, "max_limit", limitation->max_limit);
    }
    if (limitation->max_subid_length > 0) {
        cJSON_AddNumberToObject(obj, "max_subid_length", limitation->max_subid_length);
    }
    if (limitation->max_event_tags > 0) {
        cJSON_AddNumberToObject(obj, "max_event_tags", limitation->max_event_tags);
    }
    if (limitation->max_content_length > 0) {
        cJSON_AddNumberToObject(obj, "max_content_length", limitation->max_content_length);
    }
    if (limitation->min_pow_difficulty > 0) {
        cJSON_AddNumberToObject(obj, "min_pow_difficulty", limitation->min_pow_difficulty);
    }
    cJSON_AddBoolToObject(obj, "auth_required", limitation->auth_required);
    cJSON_AddBoolToObject(obj, "payment_required", limitation->payment_required);
    cJSON_AddBoolToObject(obj, "restricted_writes", limitation->restricted_writes);
    if (limitation->created_at_lower_limit > 0) {
        cJSON_AddNumberToObject(obj, "created_at_lower_limit", (double)limitation->created_at_lower_limit);
    }
    if (limitation->created_at_upper_limit > 0) {
        cJSON_AddNumberToObject(obj, "created_at_upper_limit", (double)limitation->created_at_upper_limit);
    }
    if (limitation->default_limit > 0) {
        cJSON_AddNumberToObject(obj, "default_limit", limitation->default_limit);
    }

    char* json_str = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);

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

nostr_relay_error_t nostr_relay_info_serialize(const nostr_relay_info_t* info,
                                               char* buf, size_t buf_size, size_t* out_len)
{
    if (!info || !buf || buf_size == 0) {
        return NOSTR_RELAY_ERR_INVALID_JSON;
    }

    cJSON* obj = cJSON_CreateObject();
    if (!obj) {
        return NOSTR_RELAY_ERR_MEMORY;
    }

    if (info->name) {
        cJSON_AddStringToObject(obj, "name", info->name);
    }
    if (info->description) {
        cJSON_AddStringToObject(obj, "description", info->description);
    }
    if (info->banner) {
        cJSON_AddStringToObject(obj, "banner", info->banner);
    }
    if (info->icon) {
        cJSON_AddStringToObject(obj, "icon", info->icon);
    }
    if (info->pubkey) {
        cJSON_AddStringToObject(obj, "pubkey", info->pubkey);
    }
    if (info->self_pubkey) {
        cJSON_AddStringToObject(obj, "self", info->self_pubkey);
    }
    if (info->contact) {
        cJSON_AddStringToObject(obj, "contact", info->contact);
    }

    cJSON* nips_arr = cJSON_CreateArray();
    if (!nips_arr) {
        cJSON_Delete(obj);
        return NOSTR_RELAY_ERR_MEMORY;
    }
    for (size_t i = 0; i < info->supported_nips_count; i++) {
        cJSON_AddItemToArray(nips_arr, cJSON_CreateNumber(info->supported_nips[i]));
    }
    cJSON_AddItemToObject(obj, "supported_nips", nips_arr);

    if (info->software) {
        cJSON_AddStringToObject(obj, "software", info->software);
    }
    if (info->version) {
        cJSON_AddStringToObject(obj, "version", info->version);
    }
    if (info->privacy_policy) {
        cJSON_AddStringToObject(obj, "privacy_policy", info->privacy_policy);
    }
    if (info->terms_of_service) {
        cJSON_AddStringToObject(obj, "terms_of_service", info->terms_of_service);
    }

    cJSON* limitation_obj = cJSON_CreateObject();
    if (info->limitation.max_message_length > 0) {
        cJSON_AddNumberToObject(limitation_obj, "max_message_length", info->limitation.max_message_length);
    }
    if (info->limitation.max_subscriptions > 0) {
        cJSON_AddNumberToObject(limitation_obj, "max_subscriptions", info->limitation.max_subscriptions);
    }
    if (info->limitation.max_filters > 0) {
        cJSON_AddNumberToObject(limitation_obj, "max_filters", info->limitation.max_filters);
    }
    if (info->limitation.max_limit > 0) {
        cJSON_AddNumberToObject(limitation_obj, "max_limit", info->limitation.max_limit);
    }
    if (info->limitation.max_subid_length > 0) {
        cJSON_AddNumberToObject(limitation_obj, "max_subid_length", info->limitation.max_subid_length);
    }
    if (info->limitation.max_event_tags > 0) {
        cJSON_AddNumberToObject(limitation_obj, "max_event_tags", info->limitation.max_event_tags);
    }
    if (info->limitation.max_content_length > 0) {
        cJSON_AddNumberToObject(limitation_obj, "max_content_length", info->limitation.max_content_length);
    }
    if (info->limitation.min_pow_difficulty > 0) {
        cJSON_AddNumberToObject(limitation_obj, "min_pow_difficulty", info->limitation.min_pow_difficulty);
    }
    cJSON_AddBoolToObject(limitation_obj, "auth_required", info->limitation.auth_required);
    cJSON_AddBoolToObject(limitation_obj, "payment_required", info->limitation.payment_required);
    cJSON_AddBoolToObject(limitation_obj, "restricted_writes", info->limitation.restricted_writes);
    if (info->limitation.created_at_lower_limit > 0) {
        cJSON_AddNumberToObject(limitation_obj, "created_at_lower_limit", (double)info->limitation.created_at_lower_limit);
    }
    if (info->limitation.created_at_upper_limit > 0) {
        cJSON_AddNumberToObject(limitation_obj, "created_at_upper_limit", (double)info->limitation.created_at_upper_limit);
    }
    if (info->limitation.default_limit > 0) {
        cJSON_AddNumberToObject(limitation_obj, "default_limit", info->limitation.default_limit);
    }
    cJSON_AddItemToObject(obj, "limitation", limitation_obj);

    if (info->retention_count > 0 && info->retention) {
        cJSON* retention_arr = cJSON_CreateArray();
        for (size_t i = 0; i < info->retention_count; i++) {
            cJSON* ret_obj = cJSON_CreateObject();
            if (info->retention[i].kinds_count > 0) {
                cJSON* kinds_arr = cJSON_CreateArray();
                for (size_t j = 0; j < info->retention[i].kinds_count; j++) {
                    cJSON_AddItemToArray(kinds_arr, cJSON_CreateNumber(info->retention[i].kinds[j]));
                }
                cJSON_AddItemToObject(ret_obj, "kinds", kinds_arr);
            }
            if (info->retention[i].time != 0) {
                cJSON_AddNumberToObject(ret_obj, "time", (double)info->retention[i].time);
            }
            if (info->retention[i].count > 0) {
                cJSON_AddNumberToObject(ret_obj, "count", info->retention[i].count);
            }
            cJSON_AddItemToArray(retention_arr, ret_obj);
        }
        cJSON_AddItemToObject(obj, "retention", retention_arr);
    }

    if (info->relay_countries_count > 0 && info->relay_countries) {
        cJSON* countries_arr = cJSON_CreateArray();
        for (size_t i = 0; i < info->relay_countries_count; i++) {
            cJSON_AddItemToArray(countries_arr, cJSON_CreateString(info->relay_countries[i]));
        }
        cJSON_AddItemToObject(obj, "relay_countries", countries_arr);
    }

    if (info->language_tags_count > 0 && info->language_tags) {
        cJSON* langs_arr = cJSON_CreateArray();
        for (size_t i = 0; i < info->language_tags_count; i++) {
            cJSON_AddItemToArray(langs_arr, cJSON_CreateString(info->language_tags[i]));
        }
        cJSON_AddItemToObject(obj, "language_tags", langs_arr);
    }

    if (info->tags_count > 0 && info->tags) {
        cJSON* tags_arr = cJSON_CreateArray();
        for (size_t i = 0; i < info->tags_count; i++) {
            cJSON_AddItemToArray(tags_arr, cJSON_CreateString(info->tags[i]));
        }
        cJSON_AddItemToObject(obj, "tags", tags_arr);
    }

    if (info->posting_policy) {
        cJSON_AddStringToObject(obj, "posting_policy", info->posting_policy);
    }
    if (info->payments_url) {
        cJSON_AddStringToObject(obj, "payments_url", info->payments_url);
    }

    bool has_fees = (info->fees.admission_count > 0 ||
                     info->fees.subscription_count > 0 ||
                     info->fees.publication_count > 0);
    if (has_fees) {
        cJSON* fees_obj = cJSON_CreateObject();

        if (info->fees.admission_count > 0 && info->fees.admission) {
            cJSON* admission_arr = cJSON_CreateArray();
            for (size_t i = 0; i < info->fees.admission_count; i++) {
                cJSON* fee_obj = cJSON_CreateObject();
                cJSON_AddNumberToObject(fee_obj, "amount", (double)info->fees.admission[i].amount);
                if (info->fees.admission[i].unit) {
                    cJSON_AddStringToObject(fee_obj, "unit", info->fees.admission[i].unit);
                }
                cJSON_AddItemToArray(admission_arr, fee_obj);
            }
            cJSON_AddItemToObject(fees_obj, "admission", admission_arr);
        }

        if (info->fees.subscription_count > 0 && info->fees.subscription) {
            cJSON* sub_arr = cJSON_CreateArray();
            for (size_t i = 0; i < info->fees.subscription_count; i++) {
                cJSON* fee_obj = cJSON_CreateObject();
                cJSON_AddNumberToObject(fee_obj, "amount", (double)info->fees.subscription[i].amount);
                if (info->fees.subscription[i].unit) {
                    cJSON_AddStringToObject(fee_obj, "unit", info->fees.subscription[i].unit);
                }
                if (info->fees.subscription[i].period > 0) {
                    cJSON_AddNumberToObject(fee_obj, "period", info->fees.subscription[i].period);
                }
                cJSON_AddItemToArray(sub_arr, fee_obj);
            }
            cJSON_AddItemToObject(fees_obj, "subscription", sub_arr);
        }

        if (info->fees.publication_count > 0 && info->fees.publication) {
            cJSON* pub_arr = cJSON_CreateArray();
            for (size_t i = 0; i < info->fees.publication_count; i++) {
                cJSON* fee_obj = cJSON_CreateObject();
                if (info->fees.publication[i].kinds_count > 0 && info->fees.publication[i].kinds) {
                    cJSON* kinds_arr = cJSON_CreateArray();
                    for (size_t j = 0; j < info->fees.publication[i].kinds_count; j++) {
                        cJSON_AddItemToArray(kinds_arr, cJSON_CreateNumber(info->fees.publication[i].kinds[j]));
                    }
                    cJSON_AddItemToObject(fee_obj, "kinds", kinds_arr);
                }
                cJSON_AddNumberToObject(fee_obj, "amount", (double)info->fees.publication[i].amount);
                if (info->fees.publication[i].unit) {
                    cJSON_AddStringToObject(fee_obj, "unit", info->fees.publication[i].unit);
                }
                cJSON_AddItemToArray(pub_arr, fee_obj);
            }
            cJSON_AddItemToObject(fees_obj, "publication", pub_arr);
        }

        cJSON_AddItemToObject(obj, "fees", fees_obj);
    }

    char* json_str = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);

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

#else

nostr_relay_error_t nostr_relay_limitation_serialize(const nostr_relay_limitation_t* limitation,
                                                     char* buf, size_t buf_size, size_t* out_len)
{
    (void)limitation;
    (void)buf;
    (void)buf_size;
    (void)out_len;
    return NOSTR_RELAY_ERR_INVALID_JSON;
}

nostr_relay_error_t nostr_relay_info_serialize(const nostr_relay_info_t* info,
                                               char* buf, size_t buf_size, size_t* out_len)
{
    (void)info;
    (void)buf;
    (void)buf_size;
    (void)out_len;
    return NOSTR_RELAY_ERR_INVALID_JSON;
}

#endif
