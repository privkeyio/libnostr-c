#include "nostr.h"

#ifdef NOSTR_FEATURE_NIP25

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>

#define REACTION_KIND 7

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

nostr_error_t nostr_reaction_create(nostr_event** event, const char* reaction_content,
                                    const char* target_event_id, const char* target_pubkey,
                                    const char* relay_hint, uint16_t target_kind)
{
    if (!event || !target_event_id || !target_pubkey)
        return NOSTR_ERR_INVALID_PARAM;

    if (!is_valid_hex_string(target_event_id, 64) || !is_valid_hex_string(target_pubkey, 64))
        return NOSTR_ERR_INVALID_PARAM;

    nostr_error_t err = nostr_event_create(event);
    if (err != NOSTR_OK)
        return err;

    (*event)->kind = REACTION_KIND;

    err = nostr_event_set_content(*event, reaction_content ? reaction_content : "+");
    if (err != NOSTR_OK) {
        cleanup_event(event);
        return err;
    }

    const char* e_tag[4] = {"e", target_event_id, relay_hint, target_pubkey};
    err = nostr_event_add_tag(*event, e_tag, relay_hint ? 4 : 2);
    if (err != NOSTR_OK) {
        cleanup_event(event);
        return err;
    }

    const char* p_tag[3] = {"p", target_pubkey, relay_hint};
    err = nostr_event_add_tag(*event, p_tag, relay_hint ? 3 : 2);
    if (err != NOSTR_OK) {
        cleanup_event(event);
        return err;
    }

    if (target_kind > 0) {
        char kind_str[16];
        snprintf(kind_str, sizeof(kind_str), "%u", target_kind);
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

nostr_error_t nostr_reaction_parse(const nostr_event* event, char* reaction_content, size_t content_size,
                                   char* target_event_id, size_t event_id_size,
                                   char* target_pubkey, size_t pubkey_size,
                                   uint16_t* target_kind)
{
    if (!event)
        return NOSTR_ERR_INVALID_PARAM;

    if (event->kind != REACTION_KIND)
        return NOSTR_ERR_INVALID_EVENT;

    copy_str_safe(reaction_content, content_size, event->content);
    copy_str_safe(target_event_id, event_id_size, NULL);
    copy_str_safe(target_pubkey, pubkey_size, NULL);
    if (target_kind)
        *target_kind = 0;

    const char* last_e_id = NULL;
    const char* last_p_key = NULL;

    if (!event->tags && event->tags_count > 0) {
        return NOSTR_ERR_NOT_FOUND;
    }

    for (size_t i = 0; i < event->tags_count; i++) {
        const nostr_tag* tag = &event->tags[i];
        if (tag->count < 2 || !tag->values[0] || !tag->values[1])
            continue;

        const char* name = tag->values[0];
        const char* value = tag->values[1];

        if (strcmp(name, "e") == 0) {
            last_e_id = value;
        } else if (strcmp(name, "p") == 0) {
            last_p_key = value;
        } else if (strcmp(name, "k") == 0 && target_kind) {
            char* endptr;
            errno = 0;
            unsigned long kind_val = strtoul(value, &endptr, 10);
            if (errno == 0 && endptr != value && *endptr == '\0') {
                *target_kind = (kind_val > UINT16_MAX) ? UINT16_MAX : (uint16_t)kind_val;
            }
        }
    }

    copy_str_safe(target_event_id, event_id_size, last_e_id);
    copy_str_safe(target_pubkey, pubkey_size, last_p_key);

    return last_e_id ? NOSTR_OK : NOSTR_ERR_NOT_FOUND;
}

nostr_error_t nostr_reaction_is_like(const nostr_event* event, int* is_like)
{
    if (!event || !is_like)
        return NOSTR_ERR_INVALID_PARAM;

    if (event->kind != REACTION_KIND)
        return NOSTR_ERR_INVALID_EVENT;

    *is_like = (!event->content || event->content[0] == '\0' ||
                strcmp(event->content, "+") == 0);
    return NOSTR_OK;
}

nostr_error_t nostr_reaction_is_dislike(const nostr_event* event, int* is_dislike)
{
    if (!event || !is_dislike)
        return NOSTR_ERR_INVALID_PARAM;

    if (event->kind != REACTION_KIND)
        return NOSTR_ERR_INVALID_EVENT;

    *is_dislike = (event->content && strcmp(event->content, "-") == 0);
    return NOSTR_OK;
}

#else

nostr_error_t nostr_reaction_create(nostr_event** event, const char* reaction_content,
                                    const char* target_event_id, const char* target_pubkey,
                                    const char* relay_hint, uint16_t target_kind)
{
    (void)event; (void)reaction_content; (void)target_event_id;
    (void)target_pubkey; (void)relay_hint; (void)target_kind;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_reaction_parse(const nostr_event* event, char* reaction_content, size_t content_size,
                                   char* target_event_id, size_t event_id_size,
                                   char* target_pubkey, size_t pubkey_size,
                                   uint16_t* target_kind)
{
    (void)event; (void)reaction_content; (void)content_size;
    (void)target_event_id; (void)event_id_size;
    (void)target_pubkey; (void)pubkey_size; (void)target_kind;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_reaction_is_like(const nostr_event* event, int* is_like)
{
    (void)event; (void)is_like;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_reaction_is_dislike(const nostr_event* event, int* is_dislike)
{
    (void)event; (void)is_dislike;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif
