#include "nostr.h"

#ifdef NOSTR_FEATURE_NIP18

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

#define REPOST_KIND 6
#define GENERIC_REPOST_KIND 16

static int is_valid_hex_string(const char* str, size_t expected_len)
{
    if (!str)
        return 0;
    size_t len = strlen(str);
    if (len != expected_len)
        return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)str[i]))
            return 0;
    }
    return 1;
}

static void cleanup_event(nostr_event** event)
{
    nostr_event_destroy(*event);
    *event = NULL;
}

nostr_error_t nostr_repost_create(nostr_event** event, const char* reposted_event_id,
                                  const char* reposted_pubkey, const char* relay_hint,
                                  uint16_t reposted_kind, const char* embedded_json)
{
    if (!event || !reposted_event_id || !reposted_pubkey || !relay_hint)
        return NOSTR_ERR_INVALID_PARAM;

    if (!is_valid_hex_string(reposted_event_id, 64) || !is_valid_hex_string(reposted_pubkey, 64))
        return NOSTR_ERR_INVALID_PARAM;

    nostr_error_t err = nostr_event_create(event);
    if (err != NOSTR_OK)
        return err;

    (*event)->kind = (reposted_kind == 1) ? REPOST_KIND : GENERIC_REPOST_KIND;

    err = nostr_event_set_content(*event, embedded_json ? embedded_json : "");
    if (err != NOSTR_OK) {
        cleanup_event(event);
        return err;
    }

    const char* e_tag[3] = {"e", reposted_event_id, relay_hint};
    err = nostr_event_add_tag(*event, e_tag, 3);
    if (err != NOSTR_OK) {
        cleanup_event(event);
        return err;
    }

    const char* p_tag[2] = {"p", reposted_pubkey};
    err = nostr_event_add_tag(*event, p_tag, 2);
    if (err != NOSTR_OK) {
        cleanup_event(event);
        return err;
    }

    if ((*event)->kind == GENERIC_REPOST_KIND) {
        char kind_str[16];
        snprintf(kind_str, sizeof(kind_str), "%u", reposted_kind);
        const char* k_tag[] = {"k", kind_str};
        err = nostr_event_add_tag(*event, k_tag, 2);
        if (err != NOSTR_OK) {
            cleanup_event(event);
            return err;
        }
    }

    return NOSTR_OK;
}

static void copy_str_safe(char* dest, size_t dest_size, const char* src)
{
    if (!dest || dest_size == 0)
        return;
    if (!src) {
        dest[0] = '\0';
        return;
    }
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

nostr_error_t nostr_repost_parse(const nostr_event* event, char* reposted_event_id, size_t event_id_size,
                                 char* reposted_pubkey, size_t pubkey_size,
                                 char* relay_hint, size_t relay_hint_size,
                                 uint16_t* reposted_kind)
{
    if (!event)
        return NOSTR_ERR_INVALID_PARAM;

    if (event->kind != REPOST_KIND && event->kind != GENERIC_REPOST_KIND)
        return NOSTR_ERR_INVALID_EVENT;

    copy_str_safe(reposted_event_id, event_id_size, NULL);
    copy_str_safe(reposted_pubkey, pubkey_size, NULL);
    copy_str_safe(relay_hint, relay_hint_size, NULL);
    if (reposted_kind)
        *reposted_kind = (event->kind == REPOST_KIND) ? 1 : 0;

    const char* found_e_id = NULL;
    const char* found_relay = NULL;
    const char* found_p_key = NULL;

    if (!event->tags && event->tags_count > 0) {
        return NOSTR_ERR_NOT_FOUND;
    }

    for (size_t i = 0; i < event->tags_count; i++) {
        const nostr_tag* tag = &event->tags[i];
        if (tag->count < 2 || !tag->values || !tag->values[0] || !tag->values[1])
            continue;

        const char* name = tag->values[0];
        const char* value = tag->values[1];

        if (strcmp(name, "e") == 0) {
            found_e_id = value;
            if (tag->count >= 3 && tag->values[2]) {
                found_relay = tag->values[2];
            }
        } else if (strcmp(name, "p") == 0) {
            found_p_key = value;
        } else if (strcmp(name, "k") == 0 && reposted_kind) {
            char* endptr;
            errno = 0;
            unsigned long kind_val = strtoul(value, &endptr, 10);
            if (errno == 0 && endptr != value && *endptr == '\0' && kind_val <= UINT16_MAX) {
                *reposted_kind = (uint16_t)kind_val;
            }
        }
    }

    copy_str_safe(reposted_event_id, event_id_size, found_e_id);
    copy_str_safe(reposted_pubkey, pubkey_size, found_p_key);
    copy_str_safe(relay_hint, relay_hint_size, found_relay);

    return found_e_id ? NOSTR_OK : NOSTR_ERR_NOT_FOUND;
}

#else

nostr_error_t nostr_repost_create(nostr_event** event, const char* reposted_event_id,
                                  const char* reposted_pubkey, const char* relay_hint,
                                  uint16_t reposted_kind, const char* embedded_json)
{
    (void)event; (void)reposted_event_id; (void)reposted_pubkey;
    (void)relay_hint; (void)reposted_kind; (void)embedded_json;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_repost_parse(const nostr_event* event, char* reposted_event_id, size_t event_id_size,
                                 char* reposted_pubkey, size_t pubkey_size,
                                 char* relay_hint, size_t relay_hint_size,
                                 uint16_t* reposted_kind)
{
    (void)event; (void)reposted_event_id; (void)event_id_size;
    (void)reposted_pubkey; (void)pubkey_size;
    (void)relay_hint; (void)relay_hint_size; (void)reposted_kind;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif
