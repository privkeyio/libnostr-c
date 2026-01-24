#include "nostr.h"

#ifdef NOSTR_FEATURE_NIP18

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

#define REPOST_KIND 6
#define GENERIC_REPOST_KIND 16
#define NOSTR_URI_PREFIX "nostr:"
#define NOSTR_URI_PREFIX_LEN 6

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
                                  uint16_t reposted_kind, const char* d_tag,
                                  const char* embedded_json)
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

    if (d_tag) {
        char a_value[256];
        snprintf(a_value, sizeof(a_value), "%u:%s:%s", reposted_kind, reposted_pubkey, d_tag);
        const char* a_tag[2] = {"a", a_value};
        err = nostr_event_add_tag(*event, a_tag, 2);
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

    const char* found_e_id = NULL;
    const char* found_relay = NULL;
    const char* found_p_key = NULL;
    uint16_t found_kind = (event->kind == REPOST_KIND) ? 1 : 0;

    for (size_t i = 0; i < event->tags_count && event->tags; i++) {
        const nostr_tag* tag = &event->tags[i];
        if (tag->count < 2 || !tag->values || !tag->values[0] || !tag->values[1])
            continue;

        const char* name = tag->values[0];
        const char* value = tag->values[1];

        if (strcmp(name, "e") == 0) {
            found_e_id = value;
            if (tag->count >= 3 && tag->values[2])
                found_relay = tag->values[2];
        } else if (strcmp(name, "p") == 0) {
            found_p_key = value;
        } else if (strcmp(name, "k") == 0) {
            char* endptr;
            errno = 0;
            unsigned long kind_val = strtoul(value, &endptr, 10);
            if (errno == 0 && endptr != value && *endptr == '\0' && kind_val <= UINT16_MAX)
                found_kind = (uint16_t)kind_val;
        }
    }

    copy_str_safe(reposted_event_id, event_id_size, found_e_id);
    copy_str_safe(reposted_pubkey, pubkey_size, found_p_key);
    copy_str_safe(relay_hint, relay_hint_size, found_relay);
    if (reposted_kind)
        *reposted_kind = found_kind;

    return found_e_id ? NOSTR_OK : NOSTR_ERR_NOT_FOUND;
}

static int is_bech32_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '1';
}

static const char* find_nostr_uri(const char* content, size_t* uri_len)
{
    const char* pos = strstr(content, NOSTR_URI_PREFIX);
    if (!pos)
        return NULL;

    const char* start = pos + NOSTR_URI_PREFIX_LEN;
    if (strncmp(start, "note1", 5) != 0 &&
        strncmp(start, "nevent1", 7) != 0 &&
        strncmp(start, "naddr1", 6) != 0)
        return NULL;

    const char* end = start;
    while (*end && is_bech32_char(*end))
        end++;

    *uri_len = (size_t)(end - pos);
    return pos;
}

nostr_error_t nostr_quote_tags_from_content(nostr_event* event)
{
    if (!event)
        return NOSTR_ERR_INVALID_PARAM;

    if (!event->content || event->content[0] == '\0')
        return NOSTR_OK;

    const char* content = event->content;
    const char* pos = content;
    size_t uri_len;

    while ((pos = find_nostr_uri(pos, &uri_len)) != NULL) {
        char* uri = malloc(uri_len + 1);
        if (!uri)
            return NOSTR_ERR_MEMORY;

        memcpy(uri, pos, uri_len);
        uri[uri_len] = '\0';

        nostr_uri parsed;
        nostr_error_t err = nostr_uri_parse(uri, &parsed);
        free(uri);

        if (err != NOSTR_OK) {
            pos++;
            continue;
        }

        const char* q_tag[4];
        char id_hex[65];
        char addr_str[512];

        switch (parsed.type) {
            case NOSTR_URI_NOTE:
                nostr_hex_encode(parsed.data.note, 32, id_hex);
                q_tag[0] = "q";
                q_tag[1] = id_hex;
                q_tag[2] = "";
                q_tag[3] = "";
                err = nostr_event_add_tag(event, q_tag, 4);
                break;

            case NOSTR_URI_NEVENT: {
                nostr_hex_encode(parsed.data.nevent.id, 32, id_hex);
                const char* relay = "";
                char pubkey_hex[65] = "";

                if (parsed.data.nevent.relay_count > 0 && parsed.data.nevent.relays[0])
                    relay = parsed.data.nevent.relays[0];
                if (parsed.data.nevent.has_author)
                    nostr_hex_encode(parsed.data.nevent.author.data, 32, pubkey_hex);

                q_tag[0] = "q";
                q_tag[1] = id_hex;
                q_tag[2] = relay;
                q_tag[3] = pubkey_hex;
                err = nostr_event_add_tag(event, q_tag, 4);
                nostr_nevent_free(&parsed.data.nevent);
                break;
            }

            case NOSTR_URI_NADDR: {
                char pubkey_hex[65];
                nostr_hex_encode(parsed.data.naddr.pubkey.data, 32, pubkey_hex);
                snprintf(addr_str, sizeof(addr_str), "%u:%s:%s",
                         parsed.data.naddr.kind, pubkey_hex, parsed.data.naddr.identifier);

                const char* relay = "";
                if (parsed.data.naddr.relay_count > 0 && parsed.data.naddr.relays[0])
                    relay = parsed.data.naddr.relays[0];

                q_tag[0] = "q";
                q_tag[1] = addr_str;
                q_tag[2] = relay;
                q_tag[3] = "";
                err = nostr_event_add_tag(event, q_tag, 4);
                nostr_naddr_free(&parsed.data.naddr);
                break;
            }

            default:
                err = NOSTR_OK;
                break;
        }

        if (err != NOSTR_OK)
            return err;

        pos += uri_len;
    }

    return NOSTR_OK;
}

#else

nostr_error_t nostr_repost_create(nostr_event** event, const char* reposted_event_id,
                                  const char* reposted_pubkey, const char* relay_hint,
                                  uint16_t reposted_kind, const char* d_tag,
                                  const char* embedded_json)
{
    (void)event; (void)reposted_event_id; (void)reposted_pubkey;
    (void)relay_hint; (void)reposted_kind; (void)d_tag; (void)embedded_json;
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

nostr_error_t nostr_quote_tags_from_content(nostr_event* event)
{
    (void)event;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif
