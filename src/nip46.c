#include "nostr.h"
#include "nostr_features.h"
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_CJSON
#include <cjson/cJSON.h>
#endif

#ifdef NOSTR_FEATURE_NIP46

nostr_error_t nostr_nip46_parse_request(const nostr_event* event,
                                        const nostr_privkey* recipient_privkey,
                                        nostr_nip46_request_t* request) {
    if (!event || !recipient_privkey || !request) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    memset(request, 0, sizeof(*request));

    if (event->kind != NOSTR_NIP46_KIND) {
        return NOSTR_ERR_INVALID_EVENT;
    }

    memcpy(&request->sender_pubkey, &event->pubkey, sizeof(nostr_key));

#ifdef NOSTR_FEATURE_NIP44
    char* decrypted = NULL;
    size_t decrypted_len = 0;
    nostr_error_t err = nostr_nip44_decrypt(recipient_privkey, &event->pubkey,
                                            event->content, &decrypted, &decrypted_len);
    if (err != NOSTR_OK) {
        return err;
    }

#ifdef HAVE_CJSON
    cJSON* root = cJSON_Parse(decrypted);
    free(decrypted);
    if (!root) {
        return NOSTR_ERR_JSON_PARSE;
    }

    cJSON* id = cJSON_GetObjectItem(root, "id");
    if (id && cJSON_IsString(id)) {
        strncpy(request->id, id->valuestring, sizeof(request->id) - 1);
    }

    cJSON* method = cJSON_GetObjectItem(root, "method");
    if (method && cJSON_IsString(method)) {
        strncpy(request->method, method->valuestring, sizeof(request->method) - 1);
    }

    cJSON* params = cJSON_GetObjectItem(root, "params");
    if (params) {
        char* params_str = cJSON_PrintUnformatted(params);
        if (params_str) {
            request->params = params_str;
            request->params_len = strlen(params_str);
        }
    }

    cJSON_Delete(root);
    return NOSTR_OK;
#else
    free(decrypted);
    return NOSTR_ERR_NOT_SUPPORTED;
#endif
#else
    return NOSTR_ERR_NOT_SUPPORTED;
#endif
}

nostr_error_t nostr_nip46_create_response(const nostr_nip46_response_t* response,
                                          const nostr_privkey* signer_privkey,
                                          const nostr_key* recipient_pubkey,
                                          nostr_event** event_out) {
    if (!response || !signer_privkey || !recipient_pubkey || !event_out) {
        return NOSTR_ERR_INVALID_PARAM;
    }

#if defined(NOSTR_FEATURE_NIP44) && defined(HAVE_CJSON)
    cJSON* content_obj = cJSON_CreateObject();
    if (!content_obj) {
        return NOSTR_ERR_MEMORY;
    }

    cJSON_AddStringToObject(content_obj, "id", response->id);

    if (response->error) {
        cJSON_AddStringToObject(content_obj, "error", response->error);
    } else if (response->result) {
        cJSON* result_json = cJSON_Parse(response->result);
        if (result_json) {
            cJSON_AddItemToObject(content_obj, "result", result_json);
        } else {
            cJSON_AddStringToObject(content_obj, "result", response->result);
        }
    }

    char* content_str = cJSON_PrintUnformatted(content_obj);
    cJSON_Delete(content_obj);
    if (!content_str) {
        return NOSTR_ERR_MEMORY;
    }

    char* encrypted = NULL;
    nostr_error_t err = nostr_nip44_encrypt(signer_privkey, recipient_pubkey,
                                            content_str, strlen(content_str), &encrypted);
    free(content_str);
    if (err != NOSTR_OK) {
        return err;
    }

    err = nostr_event_create(event_out);
    if (err != NOSTR_OK) {
        free(encrypted);
        return err;
    }

    (*event_out)->kind = NOSTR_NIP46_KIND;
    err = nostr_event_set_content(*event_out, encrypted);
    free(encrypted);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*event_out);
        *event_out = NULL;
        return err;
    }

    char pubkey_hex[65];
    nostr_key_to_hex(recipient_pubkey, pubkey_hex, sizeof(pubkey_hex));
    const char* p_tag[] = {"p", pubkey_hex};
    nostr_event_add_tag(*event_out, p_tag, 2);

    err = nostr_event_compute_id(*event_out);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*event_out);
        *event_out = NULL;
        return err;
    }

    err = nostr_event_sign(*event_out, signer_privkey);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*event_out);
        *event_out = NULL;
        return err;
    }

    return NOSTR_OK;
#else
    return NOSTR_ERR_NOT_SUPPORTED;
#endif
}

void nostr_nip46_request_free(nostr_nip46_request_t* request) {
    if (request && request->params) {
        free(request->params);
        request->params = NULL;
        request->params_len = 0;
    }
}

void nostr_nip46_response_free(nostr_nip46_response_t* response) {
    if (!response) {
        return;
    }
    free(response->result);
    response->result = NULL;
    free(response->error);
    response->error = NULL;
}

#else

nostr_error_t nostr_nip46_parse_request(const nostr_event* event,
                                        const nostr_privkey* recipient_privkey,
                                        nostr_nip46_request_t* request) {
    (void)event; (void)recipient_privkey; (void)request;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nip46_create_response(const nostr_nip46_response_t* response,
                                          const nostr_privkey* signer_privkey,
                                          const nostr_key* recipient_pubkey,
                                          nostr_event** event_out) {
    (void)response; (void)signer_privkey; (void)recipient_pubkey; (void)event_out;
    return NOSTR_ERR_NOT_SUPPORTED;
}

void nostr_nip46_request_free(nostr_nip46_request_t* request) {
    (void)request;
}

void nostr_nip46_response_free(nostr_nip46_response_t* response) {
    (void)response;
}

#endif
