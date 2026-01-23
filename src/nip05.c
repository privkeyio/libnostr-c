#include "nostr.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>

#ifdef NOSTR_FEATURE_NIP05

#define NIP05_MAX_NAME_LEN 64
#define NIP05_MAX_DOMAIN_LEN 256
#define NIP05_MAX_URL_LEN 512
#define NIP05_MAX_RELAYS 100

static int is_valid_local_part(const char* s, size_t len) {
    if (len == 0 || len > NIP05_MAX_NAME_LEN) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) {
            return 0;
        }
    }
    return 1;
}

static int is_valid_domain(const char* s, size_t len) {
    if (len == 0 || len > NIP05_MAX_DOMAIN_LEN) return 0;
    if (s[0] == '.' || s[len - 1] == '.') return 0;
    int has_dot = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '.') {
            has_dot = 1;
            if (i > 0 && s[i - 1] == '.') return 0;
        } else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9') || c == '-')) {
            return 0;
        }
    }
    return has_dot;
}

static const char* skip_json_whitespace(const char* p) {
    if (!p) return p;
    while (*p == ' ' || *p == ':' || *p == '\n' || *p == '\t' || *p == '\r') p++;
    return p;
}

nostr_error_t nostr_nip05_parse(const char* identifier, char* name, size_t name_size,
                                char* domain, size_t domain_size) {
    if (!identifier || !name || !domain) return NOSTR_ERR_INVALID_PARAM;
    if (name_size < 2 || domain_size < 4) return NOSTR_ERR_INVALID_PARAM;

    const char* at = strchr(identifier, '@');
    if (!at) return NOSTR_ERR_INVALID_PARAM;

    size_t name_len = at - identifier;
    size_t domain_len = strlen(at + 1);

    if (!is_valid_local_part(identifier, name_len)) return NOSTR_ERR_INVALID_PARAM;
    if (!is_valid_domain(at + 1, domain_len)) return NOSTR_ERR_INVALID_PARAM;

    if (name_len >= name_size || domain_len >= domain_size) return NOSTR_ERR_INVALID_PARAM;

    memcpy(name, identifier, name_len);
    name[name_len] = '\0';

    memcpy(domain, at + 1, domain_len);
    domain[domain_len] = '\0';

    for (size_t i = 0; i < name_len; i++) {
        name[i] = tolower((unsigned char)name[i]);
    }
    for (size_t i = 0; i < domain_len; i++) {
        domain[i] = tolower((unsigned char)domain[i]);
    }

    return NOSTR_OK;
}

/*
 * Note: This function builds a URL from validated name and domain components.
 * SSRF protection is the responsibility of the HTTP callback implementation.
 * Callers should implement appropriate safeguards such as:
 * - Blocking private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, ::1)
 * - DNS rebinding protection
 * - Request timeouts
 * - Following redirect limits
 */
nostr_error_t nostr_nip05_build_url(const char* name, const char* domain,
                                    char* url, size_t url_size) {
    if (!name || !domain || !url) return NOSTR_ERR_INVALID_PARAM;

    size_t name_len = strlen(name);
    size_t domain_len = strlen(domain);
    size_t required = 8 + domain_len + 29 + name_len + 1;
    if (url_size < required) return NOSTR_ERR_INVALID_PARAM;

    char* p = url;
    memcpy(p, "https://", 8);
    p += 8;
    memcpy(p, domain, domain_len);
    p += domain_len;
    memcpy(p, "/.well-known/nostr.json?name=", 29);
    p += 29;
    memcpy(p, name, name_len);
    p += name_len;
    *p = '\0';

    return NOSTR_OK;
}

nostr_error_t nostr_nip05_parse_response(const char* json, const char* name,
                                         char* pubkey_hex, size_t pubkey_size,
                                         char*** relays, size_t* relay_count) {
    if (!json || !name || !pubkey_hex || pubkey_size < 65) return NOSTR_ERR_INVALID_PARAM;
    if (relays) *relays = NULL;
    if (relay_count) *relay_count = 0;

    size_t name_len = strlen(name);
    if (name_len == 0 || name_len > NIP05_MAX_NAME_LEN) return NOSTR_ERR_INVALID_PARAM;
    for (size_t i = 0; i < name_len; i++) {
        if (name[i] == '"' || name[i] == '\\') return NOSTR_ERR_INVALID_PARAM;
    }

    const char* names_pos = strstr(json, "\"names\"");
    if (!names_pos) return NOSTR_ERR_NOT_FOUND;

    names_pos = skip_json_whitespace(names_pos + 7);
    if (*names_pos != '{') return NOSTR_ERR_JSON_PARSE;

    char search_name[NIP05_MAX_NAME_LEN + 4];
    snprintf(search_name, sizeof(search_name), "\"%s\"", name);

    const char* name_pos = strstr(names_pos, search_name);
    if (!name_pos) return NOSTR_ERR_NOT_FOUND;

    name_pos = skip_json_whitespace(name_pos + strlen(search_name));
    if (*name_pos != '"') return NOSTR_ERR_JSON_PARSE;
    name_pos++;

    const char* pubkey_end = strchr(name_pos, '"');
    if (!pubkey_end || pubkey_end - name_pos != 64) return NOSTR_ERR_INVALID_KEY;

    for (size_t i = 0; i < 64; i++) {
        char c = name_pos[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return NOSTR_ERR_INVALID_KEY;
        }
        pubkey_hex[i] = tolower((unsigned char)c);
    }
    pubkey_hex[64] = '\0';

    if (!relays || !relay_count) return NOSTR_OK;

    const char* relays_pos = strstr(json, "\"relays\"");
    if (!relays_pos) return NOSTR_OK;

    relays_pos = skip_json_whitespace(relays_pos + 8);
    if (*relays_pos != '{') return NOSTR_OK;

    char pubkey_search[68];
    snprintf(pubkey_search, sizeof(pubkey_search), "\"%s\"", pubkey_hex);

    const char* pubkey_relays = strstr(relays_pos, pubkey_search);
    if (!pubkey_relays) return NOSTR_OK;

    pubkey_relays = skip_json_whitespace(pubkey_relays + strlen(pubkey_search));
    if (*pubkey_relays != '[') return NOSTR_OK;
    pubkey_relays++;

    size_t count = 0;
    const char* p = pubkey_relays;
    int in_string = 0;
    while (*p && *p != ']') {
        if (*p == '"' && (p == pubkey_relays || *(p - 1) != '\\')) {
            in_string = !in_string;
            if (!in_string) count++;
        }
        p++;
    }

    if (count == 0) return NOSTR_OK;
    if (count > NIP05_MAX_RELAYS) return NOSTR_ERR_INVALID_PARAM;
    if (count > SIZE_MAX / sizeof(char*)) return NOSTR_ERR_INVALID_PARAM;

    char** relay_array = malloc(count * sizeof(char*));
    if (!relay_array) return NOSTR_ERR_MEMORY;
    for (size_t i = 0; i < count; i++) relay_array[i] = NULL;

    size_t idx = 0;
    p = pubkey_relays;
    while (*p && *p != ']' && idx < count) {
        while (*p && *p != '"' && *p != ']') p++;
        if (*p != '"') break;
        p++;

        const char* relay_start = p;
        while (*p && (*p != '"' || (p > relay_start && *(p - 1) == '\\'))) p++;
        if (*p != '"') break;

        size_t relay_len = p - relay_start;
        relay_array[idx] = malloc(relay_len + 1);
        if (!relay_array[idx]) {
            for (size_t i = 0; i < idx; i++) free(relay_array[i]);
            free(relay_array);
            return NOSTR_ERR_MEMORY;
        }
        memcpy(relay_array[idx], relay_start, relay_len);
        relay_array[idx][relay_len] = '\0';
        idx++;
        p++;
    }

    *relays = relay_array;
    *relay_count = idx;

    return NOSTR_OK;
}

void nostr_nip05_free_relays(char** relays, size_t count) {
    if (!relays) return;
    for (size_t i = 0; i < count; i++) {
        free(relays[i]);
    }
    free(relays);
}

nostr_error_t nostr_nip05_verify(const char* identifier, const char* expected_pubkey,
                                 nostr_nip05_http_callback http_callback, void* user_data,
                                 char*** relays_out, size_t* relay_count_out) {
    if (!identifier || !expected_pubkey || !http_callback) return NOSTR_ERR_INVALID_PARAM;
    if (relays_out) *relays_out = NULL;
    if (relay_count_out) *relay_count_out = 0;

    char name[NIP05_MAX_NAME_LEN + 1];
    char domain[NIP05_MAX_DOMAIN_LEN + 1];
    nostr_error_t err = nostr_nip05_parse(identifier, name, sizeof(name), domain, sizeof(domain));
    if (err != NOSTR_OK) return err;

    char url[NIP05_MAX_URL_LEN];
    err = nostr_nip05_build_url(name, domain, url, sizeof(url));
    if (err != NOSTR_OK) return err;

    char* response = NULL;
    size_t response_len = 0;
    err = http_callback(url, &response, &response_len, user_data);
    if (err != NOSTR_OK) return err;
    if (!response || response_len == 0) return NOSTR_ERR_NOT_FOUND;

    char pubkey_hex[65];
    char** relays = NULL;
    size_t relay_count = 0;

    err = nostr_nip05_parse_response(response, name, pubkey_hex, sizeof(pubkey_hex),
                                     relays_out ? &relays : NULL,
                                     relay_count_out ? &relay_count : NULL);
    free(response);

    if (err != NOSTR_OK) return err;

    char expected_lower[65];
    size_t expected_len = strlen(expected_pubkey);
    if (expected_len != 64) {
        nostr_nip05_free_relays(relays, relay_count);
        return NOSTR_ERR_INVALID_KEY;
    }
    for (size_t i = 0; i < 64; i++) {
        expected_lower[i] = tolower((unsigned char)expected_pubkey[i]);
    }
    expected_lower[64] = '\0';

    if (memcmp(pubkey_hex, expected_lower, 64) != 0) {
        nostr_nip05_free_relays(relays, relay_count);
        return NOSTR_ERR_INVALID_KEY;
    }

    if (relays_out) *relays_out = relays;
    if (relay_count_out) *relay_count_out = relay_count;

    return NOSTR_OK;
}

#else

nostr_error_t nostr_nip05_parse(const char* identifier, char* name, size_t name_size,
                                char* domain, size_t domain_size) {
    (void)identifier; (void)name; (void)name_size; (void)domain; (void)domain_size;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nip05_build_url(const char* name, const char* domain,
                                    char* url, size_t url_size) {
    (void)name; (void)domain; (void)url; (void)url_size;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nip05_parse_response(const char* json, const char* name,
                                         char* pubkey_hex, size_t pubkey_size,
                                         char*** relays, size_t* relay_count) {
    (void)json; (void)name; (void)pubkey_hex; (void)pubkey_size; (void)relays; (void)relay_count;
    return NOSTR_ERR_NOT_SUPPORTED;
}

void nostr_nip05_free_relays(char** relays, size_t count) {
    (void)relays; (void)count;
}

nostr_error_t nostr_nip05_verify(const char* identifier, const char* expected_pubkey,
                                 nostr_nip05_http_callback http_callback, void* user_data,
                                 char*** relays_out, size_t* relay_count_out) {
    (void)identifier; (void)expected_pubkey; (void)http_callback; (void)user_data;
    (void)relays_out; (void)relay_count_out;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif
