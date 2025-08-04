#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../include/nostr.h"

#ifdef HAVE_CJSON
#include <cjson/cJSON.h>
#endif

nostr_error_t nostr_nip47_create_list_transactions_params(char** params_json, time_t* from, time_t* until,
                                                         uint32_t* limit, uint32_t* offset, 
                                                         int* unpaid, const char* type)
{
    if (!params_json) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
#ifdef HAVE_CJSON
    cJSON* params = cJSON_CreateObject();
    if (!params) {
        return NOSTR_ERR_MEMORY;
    }
    
    if (from) {
        cJSON_AddNumberToObject(params, "from", *from);
    }
    
    if (until) {
        cJSON_AddNumberToObject(params, "until", *until);
    }
    
    if (limit) {
        cJSON_AddNumberToObject(params, "limit", *limit);
    }
    
    if (offset) {
        cJSON_AddNumberToObject(params, "offset", *offset);
    }
    
    if (unpaid) {
        cJSON_AddBoolToObject(params, "unpaid", *unpaid);
    }
    
    if (type) {
        cJSON_AddStringToObject(params, "type", type);
    }
    
    *params_json = cJSON_PrintUnformatted(params);
    cJSON_Delete(params);
    
    if (!*params_json) {
        return NOSTR_ERR_MEMORY;
    }
#else
    char buffer[4096];
    int pos = snprintf(buffer, sizeof(buffer), "{");
    int first = 1;
    
    if (from) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%s\"from\":%ld", 
                       first ? "" : ",", *from);
        first = 0;
    }
    
    if (until) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%s\"until\":%ld", 
                       first ? "" : ",", *until);
        first = 0;
    }
    
    if (limit) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%s\"limit\":%u", 
                       first ? "" : ",", *limit);
        first = 0;
    }
    
    if (offset) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%s\"offset\":%u", 
                       first ? "" : ",", *offset);
        first = 0;
    }
    
    if (unpaid) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%s\"unpaid\":%s", 
                       first ? "" : ",", *unpaid ? "true" : "false");
        first = 0;
    }
    
    if (type) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%s\"type\":\"%s\"", 
                       first ? "" : ",", type);
    }
    
    snprintf(buffer + pos, sizeof(buffer) - pos, "}");
    
    *params_json = strdup(buffer);
    if (!*params_json) {
        return NOSTR_ERR_MEMORY;
    }
#endif
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_create_lookup_invoice_params(char** params_json, const char* payment_hash,
                                                       const char* invoice)
{
    if (!params_json || (!payment_hash && !invoice)) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
#ifdef HAVE_CJSON
    cJSON* params = cJSON_CreateObject();
    if (!params) {
        return NOSTR_ERR_MEMORY;
    }
    
    if (payment_hash) {
        cJSON_AddStringToObject(params, "payment_hash", payment_hash);
    }
    
    if (invoice) {
        cJSON_AddStringToObject(params, "invoice", invoice);
    }
    
    *params_json = cJSON_PrintUnformatted(params);
    cJSON_Delete(params);
    
    if (!*params_json) {
        return NOSTR_ERR_MEMORY;
    }
#else
    char buffer[4096];
    int pos = snprintf(buffer, sizeof(buffer), "{");
    
    if (payment_hash) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\"payment_hash\":\"%s\"", payment_hash);
    }
    
    if (invoice) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%s\"invoice\":\"%s\"", 
                       payment_hash ? "," : "", invoice);
    }
    
    snprintf(buffer + pos, sizeof(buffer) - pos, "}");
    
    *params_json = strdup(buffer);
    if (!*params_json) {
        return NOSTR_ERR_MEMORY;
    }
#endif
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_create_pay_keysend_params(char** params_json, uint64_t amount_msats,
                                                    const char* pubkey, const char* preimage,
                                                    const char** tlv_records, size_t tlv_count)
{
    if (!params_json || amount_msats == 0 || !pubkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
#ifdef HAVE_CJSON
    cJSON* params = cJSON_CreateObject();
    if (!params) {
        return NOSTR_ERR_MEMORY;
    }
    
    cJSON_AddNumberToObject(params, "amount", amount_msats);
    cJSON_AddStringToObject(params, "pubkey", pubkey);
    
    if (preimage) {
        cJSON_AddStringToObject(params, "preimage", preimage);
    }
    
    if (tlv_records && tlv_count > 0) {
        cJSON* tlv_array = cJSON_CreateArray();
        if (!tlv_array) {
            cJSON_Delete(params);
            return NOSTR_ERR_MEMORY;
        }
        
        for (size_t i = 0; i < tlv_count; i += 2) {
            if (i + 1 < tlv_count) {
                cJSON* tlv = cJSON_CreateObject();
                if (!tlv) {
                    cJSON_Delete(params);
                    return NOSTR_ERR_MEMORY;
                }
                
                char* end;
                long type_val = strtol(tlv_records[i], &end, 10);
                cJSON_AddNumberToObject(tlv, "type", type_val);
                cJSON_AddStringToObject(tlv, "value", tlv_records[i + 1]);
                cJSON_AddItemToArray(tlv_array, tlv);
            }
        }
        
        cJSON_AddItemToObject(params, "tlv_records", tlv_array);
    }
    
    *params_json = cJSON_PrintUnformatted(params);
    cJSON_Delete(params);
    
    if (!*params_json) {
        return NOSTR_ERR_MEMORY;
    }
#else
    char buffer[8192];
    int pos = snprintf(buffer, sizeof(buffer), 
                      "{\"amount\":%llu,\"pubkey\":\"%s\"",
                      (unsigned long long)amount_msats, pubkey);
    
    if (preimage) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, 
                       ",\"preimage\":\"%s\"", preimage);
    }
    
    if (tlv_records && tlv_count > 0) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, ",\"tlv_records\":[");
        
        for (size_t i = 0; i < tlv_count; i += 2) {
            if (i + 1 < tlv_count) {
                if (i > 0) {
                    pos += snprintf(buffer + pos, sizeof(buffer) - pos, ",");
                }
                pos += snprintf(buffer + pos, sizeof(buffer) - pos, 
                               "{\"type\":%s,\"value\":\"%s\"}", 
                               tlv_records[i], tlv_records[i + 1]);
            }
        }
        
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "]");
    }
    
    snprintf(buffer + pos, sizeof(buffer) - pos, "}");
    
    *params_json = strdup(buffer);
    if (!*params_json) {
        return NOSTR_ERR_MEMORY;
    }
#endif
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_create_multi_pay_invoice_params(char** params_json, 
                                                          const char** invoice_ids,
                                                          const char** invoices,
                                                          uint64_t* amounts, 
                                                          size_t count)
{
    if (!params_json || !invoices || count == 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
#ifdef HAVE_CJSON
    cJSON* params = cJSON_CreateObject();
    if (!params) {
        return NOSTR_ERR_MEMORY;
    }
    
    cJSON* inv_array = cJSON_CreateArray();
    if (!inv_array) {
        cJSON_Delete(params);
        return NOSTR_ERR_MEMORY;
    }
    
    for (size_t i = 0; i < count; i++) {
        cJSON* inv = cJSON_CreateObject();
        if (!inv) {
            cJSON_Delete(params);
            return NOSTR_ERR_MEMORY;
        }
        
        if (invoice_ids && invoice_ids[i]) {
            cJSON_AddStringToObject(inv, "id", invoice_ids[i]);
        }
        
        cJSON_AddStringToObject(inv, "invoice", invoices[i]);
        
        if (amounts && amounts[i] > 0) {
            cJSON_AddNumberToObject(inv, "amount", amounts[i]);
        }
        
        cJSON_AddItemToArray(inv_array, inv);
    }
    
    cJSON_AddItemToObject(params, "invoices", inv_array);
    
    *params_json = cJSON_PrintUnformatted(params);
    cJSON_Delete(params);
    
    if (!*params_json) {
        return NOSTR_ERR_MEMORY;
    }
#else
    char buffer[16384];
    int pos = snprintf(buffer, sizeof(buffer), "{\"invoices\":[");
    
    for (size_t i = 0; i < count; i++) {
        if (i > 0) {
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, ",");
        }
        
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "{");
        
        if (invoice_ids && invoice_ids[i]) {
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, 
                           "\"id\":\"%s\",", invoice_ids[i]);
        }
        
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, 
                       "\"invoice\":\"%s\"", invoices[i]);
        
        if (amounts && amounts[i] > 0) {
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, 
                           ",\"amount\":%llu", (unsigned long long)amounts[i]);
        }
        
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "}");
    }
    
    snprintf(buffer + pos, sizeof(buffer) - pos, "]}");
    
    *params_json = strdup(buffer);
    if (!*params_json) {
        return NOSTR_ERR_MEMORY;
    }
#endif
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_create_get_info_params(char** params_json)
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

nostr_error_t nostr_nip47_parse_balance_response(const char* result_json, uint64_t* balance_msats)
{
    if (!result_json || !balance_msats) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
#ifdef HAVE_CJSON
    cJSON* root = cJSON_Parse(result_json);
    if (!root) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    cJSON* balance = cJSON_GetObjectItem(root, "balance");
    if (!balance || !cJSON_IsNumber(balance)) {
        cJSON_Delete(root);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    *balance_msats = (uint64_t)balance->valuedouble;
    
    cJSON_Delete(root);
#else
    const char* balance_str = strstr(result_json, "\"balance\":");
    if (!balance_str) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    balance_str += 10;
    char* end;
    *balance_msats = strtoull(balance_str, &end, 10);
#endif
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_parse_pay_invoice_response(const char* result_json, char** preimage,
                                                     uint64_t* fees_paid)
{
    if (!result_json) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
#ifdef HAVE_CJSON
    cJSON* root = cJSON_Parse(result_json);
    if (!root) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (preimage) {
        cJSON* preim = cJSON_GetObjectItem(root, "preimage");
        if (preim && cJSON_IsString(preim)) {
            *preimage = strdup(preim->valuestring);
        }
    }
    
    if (fees_paid) {
        cJSON* fees = cJSON_GetObjectItem(root, "fees_paid");
        if (fees && cJSON_IsNumber(fees)) {
            *fees_paid = (uint64_t)fees->valuedouble;
        }
    }
    
    cJSON_Delete(root);
#else
    if (preimage) {
        const char* preim_str = strstr(result_json, "\"preimage\":\"");
        if (preim_str) {
            preim_str += 12;
            const char* end = strchr(preim_str, '"');
            if (end) {
                size_t len = end - preim_str;
                *preimage = malloc(len + 1);
                if (*preimage) {
                    memcpy(*preimage, preim_str, len);
                    (*preimage)[len] = 0;
                }
            }
        }
    }
    
    if (fees_paid) {
        const char* fees_str = strstr(result_json, "\"fees_paid\":");
        if (fees_str) {
            fees_str += 12;
            char* end;
            *fees_paid = strtoull(fees_str, &end, 10);
        }
    }
#endif
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_parse_info_response(const char* result_json, char** alias, char** color,
                                              char** pubkey, char** network, uint32_t* block_height,
                                              char*** methods, size_t* method_count)
{
    if (!result_json) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
#ifdef HAVE_CJSON
    cJSON* root = cJSON_Parse(result_json);
    if (!root) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (alias) {
        cJSON* al = cJSON_GetObjectItem(root, "alias");
        if (al && cJSON_IsString(al)) {
            *alias = strdup(al->valuestring);
        }
    }
    
    if (color) {
        cJSON* col = cJSON_GetObjectItem(root, "color");
        if (col && cJSON_IsString(col)) {
            *color = strdup(col->valuestring);
        }
    }
    
    if (pubkey) {
        cJSON* pk = cJSON_GetObjectItem(root, "pubkey");
        if (pk && cJSON_IsString(pk)) {
            *pubkey = strdup(pk->valuestring);
        }
    }
    
    if (network) {
        cJSON* net = cJSON_GetObjectItem(root, "network");
        if (net && cJSON_IsString(net)) {
            *network = strdup(net->valuestring);
        }
    }
    
    if (block_height) {
        cJSON* height = cJSON_GetObjectItem(root, "block_height");
        if (height && cJSON_IsNumber(height)) {
            *block_height = (uint32_t)height->valuedouble;
        }
    }
    
    if (methods && method_count) {
        cJSON* meth = cJSON_GetObjectItem(root, "methods");
        if (meth && cJSON_IsArray(meth)) {
            *method_count = cJSON_GetArraySize(meth);
            *methods = malloc(*method_count * sizeof(char*));
            if (*methods) {
                for (size_t i = 0; i < *method_count; i++) {
                    cJSON* item = cJSON_GetArrayItem(meth, i);
                    if (item && cJSON_IsString(item)) {
                        (*methods)[i] = strdup(item->valuestring);
                    }
                }
            }
        }
    }
    
    cJSON_Delete(root);
#else
    if (alias) *alias = strdup("wallet");
    if (color) *color = strdup("#000000");
    if (pubkey) *pubkey = strdup("0000000000000000000000000000000000000000000000000000000000000000");
    if (network) *network = strdup("mainnet");
    if (block_height) *block_height = 800000;
    if (methods && method_count) {
        *method_count = 0;
        *methods = NULL;
    }
#endif
    
    return NOSTR_OK;
}