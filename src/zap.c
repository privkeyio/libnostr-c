#include "nostr.h"

#ifdef NOSTR_FEATURE_NIP57

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define ZAP_REQUEST_KIND 9734
#define ZAP_RECEIPT_KIND 9735

static int is_valid_bech32_char(char c)
{
    const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    return strchr(charset, tolower(c)) != NULL;
}

static int decode_bech32(const char* bech32, char* hrp, uint8_t* data, size_t* data_len)
{
    size_t bech32_len = strlen(bech32);
    if (bech32_len < 8 || bech32_len > 90) {
        return 0;
    }
    
    size_t separator = 0;
    for (size_t i = 0; i < bech32_len; ++i) {
        if (bech32[i] == '1') {
            separator = i;
        }
    }
    
    if (separator < 1 || separator + 7 > bech32_len) {
        return 0;
    }
    
    if (hrp) {
        memcpy(hrp, bech32, separator);
        hrp[separator] = '\0';
    }
    
    return 1;
}

nostr_error_t nostr_zap_create_request(nostr_event** event, uint64_t amount, const nostr_key* recipient, const char* lnurl, const char* content, const char** relays, size_t relays_count)
{
    if (!event || !recipient || !relays || relays_count == 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    nostr_error_t err = nostr_event_create(event);
    if (err != NOSTR_OK) {
        return err;
    }
    
    (*event)->kind = ZAP_REQUEST_KIND;
    
    if (content && content[0] != '\0') {
        err = nostr_event_set_content(*event, content);
        if (err != NOSTR_OK) {
            nostr_event_destroy(*event);
            return err;
        }
    }
    
    const char* relay_tag[16];
    relay_tag[0] = "relays";
    size_t tag_count = 1;
    for (size_t i = 0; i < relays_count && tag_count < 16; i++) {
        relay_tag[tag_count++] = relays[i];
    }
    err = nostr_event_add_tag(*event, relay_tag, tag_count);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*event);
        return err;
    }
    
    char amount_str[32];
    snprintf(amount_str, sizeof(amount_str), "%lu", (unsigned long)amount);
    const char* amount_tag[] = {"amount", amount_str};
    err = nostr_event_add_tag(*event, amount_tag, 2);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*event);
        return err;
    }
    
    if (lnurl) {
        const char* lnurl_tag[] = {"lnurl", lnurl};
        err = nostr_event_add_tag(*event, lnurl_tag, 2);
        if (err != NOSTR_OK) {
            nostr_event_destroy(*event);
            return err;
        }
    }
    
    char pubkey_hex[65];
    err = nostr_key_to_hex(recipient, pubkey_hex, sizeof(pubkey_hex));
    if (err != NOSTR_OK) {
        nostr_event_destroy(*event);
        return err;
    }
    const char* p_tag[] = {"p", pubkey_hex};
    err = nostr_event_add_tag(*event, p_tag, 2);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*event);
        return err;
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_zap_validate_lnurl(const char* lnurl, char* nostr_pubkey, bool* allows_nostr)
{
    if (!lnurl) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (strncmp(lnurl, "lnurl", 5) != 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    char hrp[32];
    uint8_t data[256];
    size_t data_len = sizeof(data);
    
    if (!decode_bech32(lnurl, hrp, data, &data_len)) {
        return NOSTR_ERR_ENCODING;
    }
    
    if (strcmp(hrp, "lnurl") != 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_zap_parse_receipt(const nostr_event* event, uint64_t* amount, char** bolt11, char* preimage, nostr_event** zap_request)
{
    if (!event || event->kind != ZAP_RECEIPT_KIND) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count < 2) {
            continue;
        }
        
        const char* tag_name = event->tags[i].values[0];
        const char* tag_value = event->tags[i].values[1];
        
        if (strcmp(tag_name, "bolt11") == 0 && bolt11) {
            *bolt11 = strdup(tag_value);
            if (!*bolt11) {
                return NOSTR_ERR_MEMORY;
            }
        } else if (strcmp(tag_name, "preimage") == 0 && preimage) {
            size_t len = strlen(tag_value);
            if (len <= 64) {
                memcpy(preimage, tag_value, len);
                preimage[len] = '\0';
            }
        } else if (strcmp(tag_name, "description") == 0 && zap_request) {
            nostr_error_t err = nostr_event_from_json(tag_value, zap_request);
            if (err != NOSTR_OK) {
                if (bolt11 && *bolt11) {
                    free(*bolt11);
                    *bolt11 = NULL;
                }
                return err;
            }
        }
    }
    
    if (amount && bolt11 && *bolt11) {
        const char* amt_start = strstr(*bolt11, "lnbc");
        if (amt_start) {
            amt_start += 4;
            char* amt_end;
            unsigned long amt = strtoul(amt_start, &amt_end, 10);
            if (amt_end > amt_start) {
                char multiplier = tolower(*amt_end);
                switch (multiplier) {
                    case 'm':
                        *amount = amt * 100000000;
                        break;
                    case 'u':
                        *amount = amt * 100000;
                        break;
                    case 'n':
                        *amount = amt * 100;
                        break;
                    case 'p':
                        *amount = amt / 10;
                        break;
                    default:
                        *amount = amt * 100000000000;
                }
            }
        }
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_zap_verify(const nostr_event* receipt, const nostr_event* request, const char* server_pubkey)
{
    if (!receipt || !request || !server_pubkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (receipt->kind != ZAP_RECEIPT_KIND || request->kind != ZAP_REQUEST_KIND) {
        return NOSTR_ERR_INVALID_EVENT;
    }
    
    char receipt_pubkey_hex[65];
    nostr_error_t err = nostr_key_to_hex(&receipt->pubkey, receipt_pubkey_hex, sizeof(receipt_pubkey_hex));
    if (err != NOSTR_OK) {
        return err;
    }
    
    if (strcmp(receipt_pubkey_hex, server_pubkey) != 0) {
        return NOSTR_ERR_INVALID_SIGNATURE;
    }
    
    uint64_t receipt_amount = 0;
    char* bolt11 = NULL;
    nostr_event* embedded_request = NULL;
    err = nostr_zap_parse_receipt(receipt, &receipt_amount, &bolt11, NULL, &embedded_request);
    if (err != NOSTR_OK) {
        return err;
    }
    
    if (!embedded_request) {
        if (bolt11) free(bolt11);
        return NOSTR_ERR_INVALID_EVENT;
    }
    
    int id_match = nostr_constant_time_memcmp(request->id, embedded_request->id, NOSTR_ID_SIZE) == 0;
    if (!id_match) {
        nostr_event_destroy(embedded_request);
        if (bolt11) free(bolt11);
        return NOSTR_ERR_INVALID_EVENT;
    }
    
    uint64_t request_amount = 0;
    for (size_t i = 0; i < request->tags_count; i++) {
        if (request->tags[i].count >= 2 && strcmp(request->tags[i].values[0], "amount") == 0) {
            request_amount = strtoull(request->tags[i].values[1], NULL, 10);
            break;
        }
    }
    
    if (request_amount > 0 && receipt_amount > 0 && request_amount != receipt_amount) {
        nostr_event_destroy(embedded_request);
        if (bolt11) free(bolt11);
        return NOSTR_ERR_INVALID_EVENT;
    }
    
    nostr_event_destroy(embedded_request);
    if (bolt11) free(bolt11);
    
    err = nostr_event_verify(receipt);
    if (err != NOSTR_OK) {
        return err;
    }
    
    return NOSTR_OK;
}

#else

/* NIP-57 functionality not available */
nostr_error_t nostr_zap_create_request(nostr_event** request, uint64_t amount_msat, const nostr_key* recipient, const char* lnurl, const char* content, const char** relays, size_t relay_count) {
    (void)request; (void)amount_msat; (void)recipient; (void)lnurl; (void)content; (void)relays; (void)relay_count;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_zap_verify(const nostr_event* receipt, const nostr_event* request, const char* server_pubkey) {
    (void)receipt; (void)request; (void)server_pubkey;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_zap_parse_receipt(const nostr_event* event, uint64_t* amount, char** bolt11, char* preimage, nostr_event** zap_request) {
    (void)event; (void)amount; (void)bolt11; (void)preimage; (void)zap_request;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif /* NOSTR_FEATURE_NIP57 */
