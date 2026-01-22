#include "nostr.h"

#ifdef NOSTR_FEATURE_NIP10

#include <stdlib.h>
#include <string.h>

typedef struct {
    char event_id[65];
    char relay_url[256];
    char marker[16];
    char pubkey[65];
} e_tag_info;

static void copy_bounded(char* dest, const char* src, size_t max_len)
{
    if (!src) {
        dest[0] = '\0';
        return;
    }
    size_t len = strlen(src);
    if (len > max_len)
        len = max_len;
    memcpy(dest, src, len);
    dest[len] = '\0';
}

static int parse_e_tag(const nostr_tag* tag, e_tag_info* info)
{
    if (!tag || !info || tag->count < 2 || !tag->values[0] || strcmp(tag->values[0], "e") != 0) {
        return 0;
    }

    if (!tag->values[1]) {
        return 0;
    }

    memset(info, 0, sizeof(*info));
    copy_bounded(info->event_id, tag->values[1], 64);

    if (tag->count >= 3 && tag->values[2])
        copy_bounded(info->relay_url, tag->values[2], 255);
    if (tag->count >= 4 && tag->values[3])
        copy_bounded(info->marker, tag->values[3], 15);
    if (tag->count >= 5 && tag->values[4])
        copy_bounded(info->pubkey, tag->values[4], 64);

    return 1;
}

static nostr_error_t collect_e_tags(const nostr_event* event, e_tag_info** out_tags, size_t* out_count)
{
    if (!event->tags && event->tags_count > 0) {
        *out_tags = NULL;
        *out_count = 0;
        return NOSTR_ERR_NOT_FOUND;
    }

    size_t count = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 && event->tags[i].values[0] &&
            strcmp(event->tags[i].values[0], "e") == 0)
            count++;
    }

    if (count == 0) {
        *out_tags = NULL;
        *out_count = 0;
        return NOSTR_ERR_NOT_FOUND;
    }

    e_tag_info* tags = calloc(count, sizeof(e_tag_info));
    if (!tags)
        return NOSTR_ERR_MEMORY;

    size_t idx = 0;
    for (size_t i = 0; i < event->tags_count && idx < count; i++) {
        if (parse_e_tag(&event->tags[i], &tags[idx]))
            idx++;
    }

    *out_tags = tags;
    *out_count = idx;
    return NOSTR_OK;
}

static void copy_id_and_relay(const e_tag_info* info, char* id, size_t id_size,
                              char* relay, size_t relay_size)
{
    strncpy(id, info->event_id, id_size - 1);
    id[id_size - 1] = '\0';
    if (relay && relay_size > 0 && info->relay_url[0]) {
        strncpy(relay, info->relay_url, relay_size - 1);
        relay[relay_size - 1] = '\0';
    }
}

nostr_error_t nostr_event_get_root_id(const nostr_event* event, char* root_id, size_t root_id_size,
                                      char* relay_hint, size_t relay_hint_size)
{
    if (!event || !root_id || root_id_size < 65)
        return NOSTR_ERR_INVALID_PARAM;

    root_id[0] = '\0';
    if (relay_hint && relay_hint_size > 0)
        relay_hint[0] = '\0';

    e_tag_info* e_tags = NULL;
    size_t e_tag_count = 0;
    nostr_error_t err = collect_e_tags(event, &e_tags, &e_tag_count);
    if (err != NOSTR_OK)
        return err;

    for (size_t i = 0; i < e_tag_count; i++) {
        if (strcmp(e_tags[i].marker, "root") == 0) {
            copy_id_and_relay(&e_tags[i], root_id, root_id_size, relay_hint, relay_hint_size);
            free(e_tags);
            return NOSTR_OK;
        }
    }

    copy_id_and_relay(&e_tags[0], root_id, root_id_size, relay_hint, relay_hint_size);
    free(e_tags);
    return NOSTR_OK;
}

nostr_error_t nostr_event_get_reply_id(const nostr_event* event, char* reply_id, size_t reply_id_size,
                                       char* relay_hint, size_t relay_hint_size)
{
    if (!event || !reply_id || reply_id_size < 65)
        return NOSTR_ERR_INVALID_PARAM;

    reply_id[0] = '\0';
    if (relay_hint && relay_hint_size > 0)
        relay_hint[0] = '\0';

    e_tag_info* e_tags = NULL;
    size_t e_tag_count = 0;
    nostr_error_t err = collect_e_tags(event, &e_tags, &e_tag_count);
    if (err != NOSTR_OK)
        return err;

    for (size_t i = 0; i < e_tag_count; i++) {
        if (strcmp(e_tags[i].marker, "reply") == 0) {
            copy_id_and_relay(&e_tags[i], reply_id, reply_id_size, relay_hint, relay_hint_size);
            free(e_tags);
            return NOSTR_OK;
        }
    }

    if (e_tag_count >= 2) {
        copy_id_and_relay(&e_tags[e_tag_count - 1], reply_id, reply_id_size, relay_hint, relay_hint_size);
        free(e_tags);
        return NOSTR_OK;
    }

    free(e_tags);
    return NOSTR_ERR_NOT_FOUND;
}

static nostr_error_t add_e_tag(nostr_event* event, const char* id, const char* relay,
                               const char* marker, const char* pubkey)
{
    const char* tag[5];
    size_t count = 4;
    tag[0] = "e";
    tag[1] = id;
    tag[2] = relay ? relay : "";
    tag[3] = marker;
    if (pubkey) {
        tag[4] = pubkey;
        count = 5;
    }
    return nostr_event_add_tag(event, tag, count);
}

nostr_error_t nostr_event_add_reply_tags(nostr_event* event, const char* root_id, const char* root_relay,
                                         const char* root_pubkey, const char* reply_id,
                                         const char* reply_relay, const char* reply_pubkey)
{
    if (!event || (!root_id && !reply_id))
        return NOSTR_ERR_INVALID_PARAM;

    nostr_error_t err;

    if (root_id) {
        err = add_e_tag(event, root_id, root_relay, "root", root_pubkey);
        if (err != NOSTR_OK)
            return err;
    }

    if (reply_id) {
        err = add_e_tag(event, reply_id, reply_relay, "reply", reply_pubkey);
        if (err != NOSTR_OK)
            return err;
    }

    return NOSTR_OK;
}

nostr_error_t nostr_event_add_mention_tag(nostr_event* event, const char* pubkey, const char* relay_hint)
{
    if (!event || !pubkey)
        return NOSTR_ERR_INVALID_PARAM;

    const char* tag[3] = {"p", pubkey, relay_hint};
    size_t count = relay_hint ? 3 : 2;
    return nostr_event_add_tag(event, tag, count);
}

nostr_error_t nostr_event_is_reply(const nostr_event* event, int* is_reply)
{
    if (!event || !is_reply)
        return NOSTR_ERR_INVALID_PARAM;

    *is_reply = 0;

    if (!event->tags && event->tags_count > 0)
        return NOSTR_OK;

    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 && event->tags[i].values[0] &&
            strcmp(event->tags[i].values[0], "e") == 0) {
            *is_reply = 1;
            return NOSTR_OK;
        }
    }

    return NOSTR_OK;
}

#else

nostr_error_t nostr_event_get_root_id(const nostr_event* event, char* root_id, size_t root_id_size,
                                      char* relay_hint, size_t relay_hint_size)
{
    (void)event; (void)root_id; (void)root_id_size;
    (void)relay_hint; (void)relay_hint_size;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_event_get_reply_id(const nostr_event* event, char* reply_id, size_t reply_id_size,
                                       char* relay_hint, size_t relay_hint_size)
{
    (void)event; (void)reply_id; (void)reply_id_size;
    (void)relay_hint; (void)relay_hint_size;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_event_add_reply_tags(nostr_event* event, const char* root_id, const char* root_relay,
                                         const char* root_pubkey, const char* reply_id,
                                         const char* reply_relay, const char* reply_pubkey)
{
    (void)event; (void)root_id; (void)root_relay; (void)root_pubkey;
    (void)reply_id; (void)reply_relay; (void)reply_pubkey;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_event_add_mention_tag(nostr_event* event, const char* pubkey, const char* relay_hint)
{
    (void)event; (void)pubkey; (void)relay_hint;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_event_is_reply(const nostr_event* event, int* is_reply)
{
    (void)event; (void)is_reply;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif
