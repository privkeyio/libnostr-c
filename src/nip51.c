#include "nostr.h"

#ifdef NOSTR_FEATURE_NIP51

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <stdint.h>

#define INITIAL_ITEM_CAPACITY 8
#define MAX_ITEM_COUNT 4096

static size_t json_escaped_len(const char* s)
{
    if (!s) return 0;
    size_t len = 0;
    for (const char* p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t') {
            len += 2;
        } else if (c < 0x20) {
            len += 6;
        } else {
            len += 1;
        }
    }
    return len;
}

static void json_escape_to(char* dest, const char* src)
{
    if (!src) return;
    while (*src) {
        unsigned char c = (unsigned char)*src++;
        switch (c) {
        case '"':  *dest++ = '\\'; *dest++ = '"';  break;
        case '\\': *dest++ = '\\'; *dest++ = '\\'; break;
        case '\n': *dest++ = '\\'; *dest++ = 'n';  break;
        case '\r': *dest++ = '\\'; *dest++ = 'r';  break;
        case '\t': *dest++ = '\\'; *dest++ = 't';  break;
        default:
            if (c < 0x20) {
                *dest++ = '\\';
                *dest++ = 'u';
                *dest++ = '0';
                *dest++ = '0';
                *dest++ = "0123456789abcdef"[c >> 4];
                *dest++ = "0123456789abcdef"[c & 0x0f];
            } else {
                *dest++ = c;
            }
            break;
        }
    }
    *dest = '\0';
}

static bool is_parameterized_list(uint16_t kind)
{
    return kind >= 30000 && kind < 40000;
}

static int hex_digit_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static bool is_valid_hex64(const char* s)
{
    if (!s || strlen(s) != 64) {
        return false;
    }
    for (size_t i = 0; i < 64; i++) {
        if (hex_digit_value(s[i]) < 0) {
            return false;
        }
    }
    return true;
}

static bool is_json_whitespace(char c)
{
    return c == ' ' || c == '\n' || c == '\r' || c == '\t';
}

static const char* skip_json_whitespace(const char* p)
{
    while (*p && (is_json_whitespace(*p) || *p == ',')) {
        p++;
    }
    return p;
}

static int parse_hex4(const char** pp)
{
    const char* p = *pp;
    unsigned int val = 0;
    for (int i = 0; i < 4; i++) {
        int d = hex_digit_value(p[i]);
        if (d < 0) return -1;
        val = (val << 4) | (unsigned int)d;
    }
    *pp = p + 4;
    return (int)val;
}

static void free_item(nostr_list_item* item)
{
    if (!item) {
        return;
    }
    free(item->tag_type);
    free(item->value);
    free(item->relay_hint);
    free(item->petname);
}

nostr_error_t nostr_list_create(nostr_list** list, uint16_t kind)
{
    if (!list) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    *list = calloc(1, sizeof(nostr_list));
    if (!*list) {
        return NOSTR_ERR_MEMORY;
    }

    (*list)->items = calloc(INITIAL_ITEM_CAPACITY, sizeof(nostr_list_item));
    if (!(*list)->items) {
        free(*list);
        *list = NULL;
        return NOSTR_ERR_MEMORY;
    }

    (*list)->kind = kind;
    (*list)->item_capacity = INITIAL_ITEM_CAPACITY;
    (*list)->item_count = 0;

    return NOSTR_OK;
}

void nostr_list_free(nostr_list* list)
{
    if (!list) {
        return;
    }

    for (size_t i = 0; i < list->item_count; i++) {
        free_item(&list->items[i]);
    }
    free(list->items);
    free(list->d_tag);
    free(list->title);
    free(list->description);
    free(list->image);
    free(list);
}

static nostr_error_t set_string_field(nostr_list* list, char** field, const char* value)
{
    if (!list) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    free(*field);
    *field = value ? strdup(value) : NULL;
    if (value && !*field) {
        return NOSTR_ERR_MEMORY;
    }
    return NOSTR_OK;
}

nostr_error_t nostr_list_set_d_tag(nostr_list* list, const char* d_tag)
{
    return set_string_field(list, &list->d_tag, d_tag);
}

nostr_error_t nostr_list_set_title(nostr_list* list, const char* title)
{
    return set_string_field(list, &list->title, title);
}

nostr_error_t nostr_list_set_description(nostr_list* list, const char* description)
{
    return set_string_field(list, &list->description, description);
}

nostr_error_t nostr_list_set_image(nostr_list* list, const char* image)
{
    return set_string_field(list, &list->image, image);
}

static nostr_error_t ensure_capacity(nostr_list* list)
{
    if (list->item_count >= list->item_capacity) {
        size_t new_capacity = list->item_capacity * 2;
        if (new_capacity < list->item_capacity) {
            return NOSTR_ERR_MEMORY;
        }
        if (new_capacity > MAX_ITEM_COUNT) {
            new_capacity = MAX_ITEM_COUNT;
        }
        if (new_capacity <= list->item_count) {
            return NOSTR_ERR_MEMORY;
        }
        if (new_capacity > SIZE_MAX / sizeof(nostr_list_item)) {
            return NOSTR_ERR_MEMORY;
        }
        nostr_list_item* new_items = realloc(list->items,
                                             new_capacity * sizeof(nostr_list_item));
        if (!new_items) {
            return NOSTR_ERR_MEMORY;
        }
        memset(&new_items[list->item_capacity], 0,
               (new_capacity - list->item_capacity) * sizeof(nostr_list_item));
        list->items = new_items;
        list->item_capacity = new_capacity;
    }
    return NOSTR_OK;
}

static nostr_error_t add_item(nostr_list* list, const char* tag_type, const char* value,
                              const char* relay_hint, const char* petname, bool is_private)
{
    if (!list || !tag_type || !value) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    nostr_error_t err = ensure_capacity(list);
    if (err != NOSTR_OK) {
        return err;
    }

    nostr_list_item* item = &list->items[list->item_count];
    item->tag_type = strdup(tag_type);
    item->value = strdup(value);
    item->relay_hint = relay_hint ? strdup(relay_hint) : NULL;
    item->petname = petname ? strdup(petname) : NULL;
    item->is_private = is_private;

    if (!item->tag_type || !item->value ||
        (relay_hint && !item->relay_hint) ||
        (petname && !item->petname)) {
        free_item(item);
        memset(item, 0, sizeof(nostr_list_item));
        return NOSTR_ERR_MEMORY;
    }

    list->item_count++;
    return NOSTR_OK;
}

nostr_error_t nostr_list_add_pubkey(nostr_list* list, const char* pubkey,
                                    const char* relay_hint, const char* petname, bool is_private)
{
    if (!is_valid_hex64(pubkey)) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    return add_item(list, "p", pubkey, relay_hint, petname, is_private);
}

nostr_error_t nostr_list_add_event(nostr_list* list, const char* event_id,
                                   const char* relay_hint, bool is_private)
{
    if (!is_valid_hex64(event_id)) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    return add_item(list, "e", event_id, relay_hint, NULL, is_private);
}

nostr_error_t nostr_list_add_hashtag(nostr_list* list, const char* hashtag, bool is_private)
{
    if (!hashtag || !*hashtag) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    return add_item(list, "t", hashtag, NULL, NULL, is_private);
}

nostr_error_t nostr_list_add_word(nostr_list* list, const char* word, bool is_private)
{
    if (!word || !*word) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    return add_item(list, "word", word, NULL, NULL, is_private);
}

nostr_error_t nostr_list_add_relay(nostr_list* list, const char* relay_url, bool is_private)
{
    if (!relay_url || !*relay_url) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    return add_item(list, "relay", relay_url, NULL, NULL, is_private);
}

nostr_error_t nostr_list_add_reference(nostr_list* list, const char* reference,
                                       const char* relay_hint, bool is_private)
{
    if (!reference || !*reference) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    return add_item(list, "a", reference, relay_hint, NULL, is_private);
}

nostr_error_t nostr_list_add_group(nostr_list* list, const char* group_id,
                                   const char* relay_url, const char* group_name, bool is_private)
{
    if (!group_id || !*group_id || !relay_url || !*relay_url) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    return add_item(list, "group", group_id, relay_url, group_name, is_private);
}

nostr_error_t nostr_list_add_emoji(nostr_list* list, const char* shortcode,
                                   const char* image_url, bool is_private)
{
    if (!shortcode || !*shortcode || !image_url || !*image_url) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    return add_item(list, "emoji", shortcode, image_url, NULL, is_private);
}

size_t nostr_list_count(const nostr_list* list)
{
    if (!list) {
        return 0;
    }
    return list->item_count;
}

const nostr_list_item* nostr_list_get(const nostr_list* list, size_t index)
{
    if (!list || index >= list->item_count) {
        return NULL;
    }
    return &list->items[index];
}

nostr_error_t nostr_list_remove(nostr_list* list, size_t index)
{
    if (!list || index >= list->item_count) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    free_item(&list->items[index]);

    if (index < list->item_count - 1) {
        memmove(&list->items[index], &list->items[index + 1],
                (list->item_count - index - 1) * sizeof(nostr_list_item));
    }

    list->item_count--;
    memset(&list->items[list->item_count], 0, sizeof(nostr_list_item));

    return NOSTR_OK;
}

static size_t count_private_items(const nostr_list* list)
{
    size_t count = 0;
    for (size_t i = 0; i < list->item_count; i++) {
        if (list->items[i].is_private) {
            count++;
        }
    }
    return count;
}

static char* build_private_content(const nostr_list* list)
{
    size_t private_count = count_private_items(list);
    if (private_count == 0) {
        return strdup("");
    }

    size_t buf_size = 2;
    for (size_t i = 0; i < list->item_count; i++) {
        const nostr_list_item* item = &list->items[i];
        if (!item->is_private) {
            continue;
        }
        size_t item_size = json_escaped_len(item->tag_type) +
                          json_escaped_len(item->value) + 16;
        if (item->relay_hint) {
            item_size += json_escaped_len(item->relay_hint) + 4;
        }
        if (item->petname) {
            item_size += json_escaped_len(item->petname) + 4;
            if (!item->relay_hint) {
                item_size += 3;
            }
        }
        if (buf_size > SIZE_MAX - item_size) {
            return NULL;
        }
        buf_size += item_size;
    }

    char* json = malloc(buf_size);
    if (!json) {
        return NULL;
    }

    char* pos = json;
    *pos++ = '[';
    bool first = true;
    for (size_t i = 0; i < list->item_count; i++) {
        const nostr_list_item* item = &list->items[i];
        if (!item->is_private) {
            continue;
        }

        if (!first) {
            *pos++ = ',';
        }
        first = false;

        *pos++ = '[';
        *pos++ = '"';
        json_escape_to(pos, item->tag_type);
        pos += strlen(pos);
        *pos++ = '"';
        *pos++ = ',';
        *pos++ = '"';
        json_escape_to(pos, item->value);
        pos += strlen(pos);
        *pos++ = '"';

        if (item->relay_hint) {
            *pos++ = ',';
            *pos++ = '"';
            json_escape_to(pos, item->relay_hint);
            pos += strlen(pos);
            *pos++ = '"';
        }
        if (item->petname) {
            if (!item->relay_hint) {
                *pos++ = ',';
                *pos++ = '"';
                *pos++ = '"';
            }
            *pos++ = ',';
            *pos++ = '"';
            json_escape_to(pos, item->petname);
            pos += strlen(pos);
            *pos++ = '"';
        }
        *pos++ = ']';
    }
    *pos++ = ']';
    *pos = '\0';

    return json;
}

nostr_error_t nostr_list_to_event(const nostr_list* list, const nostr_keypair* keypair,
                                  nostr_event** event)
{
    if (!list || !event) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    bool has_private = count_private_items(list) > 0;
    if (has_private && !keypair) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    nostr_error_t err = nostr_event_create(event);
    if (err != NOSTR_OK) {
        return err;
    }

    (*event)->kind = list->kind;
    (*event)->created_at = time(NULL);

    if (is_parameterized_list(list->kind)) {
        const char* d_values[2] = {"d", list->d_tag ? list->d_tag : ""};
        err = nostr_event_add_tag(*event, d_values, 2);
        if (err != NOSTR_OK) goto cleanup;

        if (list->title) {
            const char* title_values[2] = {"title", list->title};
            err = nostr_event_add_tag(*event, title_values, 2);
            if (err != NOSTR_OK) goto cleanup;
        }

        if (list->description) {
            const char* desc_values[2] = {"description", list->description};
            err = nostr_event_add_tag(*event, desc_values, 2);
            if (err != NOSTR_OK) goto cleanup;
        }

        if (list->image) {
            const char* img_values[2] = {"image", list->image};
            err = nostr_event_add_tag(*event, img_values, 2);
            if (err != NOSTR_OK) goto cleanup;
        }
    }

    for (size_t i = 0; i < list->item_count; i++) {
        const nostr_list_item* item = &list->items[i];
        if (item->is_private) continue;

        const char* values[4] = {item->tag_type, item->value, NULL, NULL};
        size_t count = 2;

        if (item->relay_hint) {
            values[count++] = item->relay_hint;
        }
        if (item->petname) {
            if (!item->relay_hint) values[count++] = "";
            values[count++] = item->petname;
        }

        err = nostr_event_add_tag(*event, values, count);
        if (err != NOSTR_OK) goto cleanup;
    }

    if (has_private) {
#ifdef NOSTR_FEATURE_NIP44
        char* private_json = build_private_content(list);
        if (!private_json) {
            err = NOSTR_ERR_MEMORY;
            goto cleanup;
        }

        const nostr_privkey* priv_key = nostr_keypair_private_key(keypair);
        const nostr_key* pub_key = nostr_keypair_public_key(keypair);
        if (!priv_key || !pub_key) {
            free(private_json);
            err = NOSTR_ERR_INVALID_PARAM;
            goto cleanup;
        }

        char* encrypted = NULL;
        err = nostr_nip44_encrypt(priv_key, pub_key,
                                  private_json, strlen(private_json), &encrypted);
        free(private_json);

        if (err != NOSTR_OK) {
            goto cleanup;
        }

        err = nostr_event_set_content(*event, encrypted);
        free(encrypted);
        if (err != NOSTR_OK) goto cleanup;
#else
        err = NOSTR_ERR_NOT_SUPPORTED;
        goto cleanup;
#endif
    } else {
        err = nostr_event_set_content(*event, "");
        if (err != NOSTR_OK) goto cleanup;
    }

    return NOSTR_OK;

cleanup:
    nostr_event_destroy(*event);
    *event = NULL;
    return err;
}

static size_t encode_utf8(char* dest, size_t max_len, size_t len, unsigned int cp, bool* truncated)
{
    if (cp <= 0x7F) {
        if (len < max_len) {
            dest[len++] = (char)cp;
        } else {
            *truncated = true;
        }
    } else if (cp <= 0x7FF) {
        if (len + 2 <= max_len) {
            dest[len++] = (char)(0xC0 | (cp >> 6));
            dest[len++] = (char)(0x80 | (cp & 0x3F));
        } else {
            *truncated = true;
        }
    } else if (cp <= 0xFFFF) {
        if (len + 3 <= max_len) {
            dest[len++] = (char)(0xE0 | (cp >> 12));
            dest[len++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            dest[len++] = (char)(0x80 | (cp & 0x3F));
        } else {
            *truncated = true;
        }
    } else if (cp <= 0x10FFFF) {
        if (len + 4 <= max_len) {
            dest[len++] = (char)(0xF0 | (cp >> 18));
            dest[len++] = (char)(0x80 | ((cp >> 12) & 0x3F));
            dest[len++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            dest[len++] = (char)(0x80 | (cp & 0x3F));
        } else {
            *truncated = true;
        }
    } else {
        if (len < max_len) dest[len++] = '?';
    }
    return len;
}

static nostr_error_t parse_private_content(const char* json, nostr_list* list)
{
    if (!json || strlen(json) < 2) {
        return NOSTR_OK;
    }

    const char* p = json;
    while (*p && *p != '[') {
        p++;
    }
    if (!*p) {
        return NOSTR_ERR_JSON_PARSE;
    }
    p++;

    while (*p) {
        p = skip_json_whitespace(p);
        if (*p == ']') {
            break;
        }
        if (*p != '[') {
            return NOSTR_ERR_JSON_PARSE;
        }
        p++;

        char tag_type[64] = {0};
        char value[1024] = {0};
        char relay_hint[512] = {0};
        char petname[256] = {0};
        int field = 0;

        while (*p && *p != ']') {
            p = skip_json_whitespace(p);
            if (*p == ']') {
                break;
            }

            if (*p != '"') {
                return NOSTR_ERR_JSON_PARSE;
            }
            p++;

            char* dest;
            size_t max_len;
            switch (field) {
            case 0:  dest = tag_type;   max_len = sizeof(tag_type) - 1;   break;
            case 1:  dest = value;      max_len = sizeof(value) - 1;      break;
            case 2:  dest = relay_hint; max_len = sizeof(relay_hint) - 1; break;
            case 3:  dest = petname;    max_len = sizeof(petname) - 1;    break;
            default:
                while (*p && *p != '"') p++;
                if (*p == '"') p++;
                field++;
                continue;
            }

            size_t len = 0;
            bool truncated = false;
            while (*p && *p != '"') {
                if (len >= max_len) {
                    truncated = true;
                    while (*p && *p != '"') {
                        if (*p == '\\' && *(p+1)) p++;
                        p++;
                    }
                    break;
                }
                if (*p == '\\' && *(p+1)) {
                    p++;
                    switch (*p) {
                    case 'n':  dest[len++] = '\n'; break;
                    case 'r':  dest[len++] = '\r'; break;
                    case 't':  dest[len++] = '\t'; break;
                    case '"':  dest[len++] = '"';  break;
                    case '\\': dest[len++] = '\\'; break;
                    case 'u': {
                        p++;
                        int hi = parse_hex4(&p);
                        if (hi < 0) {
                            if (len < max_len) dest[len++] = '?';
                            continue;
                        }
                        unsigned int codepoint = (unsigned int)hi;
                        if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
                            if (p[0] == '\\' && p[1] == 'u') {
                                p += 2;
                                int lo = parse_hex4(&p);
                                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                                    codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + ((unsigned int)lo - 0xDC00);
                                } else {
                                    if (len < max_len) dest[len++] = '?';
                                    continue;
                                }
                            } else {
                                if (len < max_len) dest[len++] = '?';
                                continue;
                            }
                        } else if (codepoint >= 0xDC00 && codepoint <= 0xDFFF) {
                            if (len < max_len) dest[len++] = '?';
                            continue;
                        }
                        len = encode_utf8(dest, max_len, len, codepoint, &truncated);
                        continue;
                    }
                    default:
                        dest[len++] = *p;
                        break;
                    }
                } else {
                    dest[len++] = *p;
                }
                p++;
            }
            dest[len] = '\0';

            if (truncated) {
                return NOSTR_ERR_JSON_PARSE;
            }

            if (*p == '"') {
                p++;
            }
            field++;
        }

        if (*p == ']') {
            p++;
        }

        if (tag_type[0] && value[0]) {
            nostr_error_t err = add_item(list, tag_type, value,
                                         relay_hint[0] ? relay_hint : NULL,
                                         petname[0] ? petname : NULL, true);
            if (err != NOSTR_OK) {
                return err;
            }
        }
    }

    return NOSTR_OK;
}

nostr_error_t nostr_list_from_event(const nostr_event* event, const nostr_keypair* keypair,
                                    nostr_list** list)
{
    if (!event || !list) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    nostr_error_t err = nostr_list_create(list, event->kind);
    if (err != NOSTR_OK) {
        return err;
    }

    for (size_t i = 0; i < event->tags_count; i++) {
        const nostr_tag* tag = &event->tags[i];
        if (tag->count < 2 || !tag->values || !tag->values[0] || !tag->values[1]) {
            continue;
        }

        const char* tag_type = tag->values[0];
        const char* value = tag->values[1];

        if (strcmp(tag_type, "d") == 0) {
            err = nostr_list_set_d_tag(*list, value);
            if (err != NOSTR_OK) goto cleanup;
            continue;
        }
        if (strcmp(tag_type, "title") == 0) {
            err = nostr_list_set_title(*list, value);
            if (err != NOSTR_OK) goto cleanup;
            continue;
        }
        if (strcmp(tag_type, "description") == 0) {
            err = nostr_list_set_description(*list, value);
            if (err != NOSTR_OK) goto cleanup;
            continue;
        }
        if (strcmp(tag_type, "image") == 0) {
            err = nostr_list_set_image(*list, value);
            if (err != NOSTR_OK) goto cleanup;
            continue;
        }

        const char* relay_hint = (tag->count >= 3 && tag->values[2]) ? tag->values[2] : NULL;
        const char* petname = (tag->count >= 4 && tag->values[3]) ? tag->values[3] : NULL;

        err = add_item(*list, tag_type, value, relay_hint, petname, false);
        if (err != NOSTR_OK) goto cleanup;
    }

    if (event->content && *event->content && keypair) {
#ifdef NOSTR_FEATURE_NIP44
        const nostr_privkey* priv_key = nostr_keypair_private_key(keypair);
        const nostr_key* pub_key = nostr_keypair_public_key(keypair);
        if (!priv_key || !pub_key) {
            err = NOSTR_ERR_INVALID_PARAM;
            goto cleanup;
        }

        char* decrypted = NULL;
        size_t decrypted_len = 0;

        err = nostr_nip44_decrypt(priv_key, pub_key,
                                  event->content, &decrypted, &decrypted_len);

        if (err != NOSTR_OK) {
            goto cleanup;
        }
        if (decrypted) {
            err = parse_private_content(decrypted, *list);
            free(decrypted);
            if (err != NOSTR_OK) goto cleanup;
        }
#else
        err = NOSTR_ERR_NOT_SUPPORTED;
        goto cleanup;
#endif
    }

    return NOSTR_OK;

cleanup:
    nostr_list_free(*list);
    *list = NULL;
    return err;
}

#else

nostr_error_t nostr_list_create(nostr_list** list, uint16_t kind)
{
    (void)list; (void)kind;
    return NOSTR_ERR_NOT_SUPPORTED;
}

void nostr_list_free(nostr_list* list)
{
    (void)list;
}

nostr_error_t nostr_list_set_d_tag(nostr_list* list, const char* d_tag)
{
    (void)list; (void)d_tag;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_list_set_title(nostr_list* list, const char* title)
{
    (void)list; (void)title;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_list_set_description(nostr_list* list, const char* description)
{
    (void)list; (void)description;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_list_set_image(nostr_list* list, const char* image)
{
    (void)list; (void)image;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_list_add_pubkey(nostr_list* list, const char* pubkey,
                                    const char* relay_hint, const char* petname, bool is_private)
{
    (void)list; (void)pubkey; (void)relay_hint; (void)petname; (void)is_private;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_list_add_event(nostr_list* list, const char* event_id,
                                   const char* relay_hint, bool is_private)
{
    (void)list; (void)event_id; (void)relay_hint; (void)is_private;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_list_add_hashtag(nostr_list* list, const char* hashtag, bool is_private)
{
    (void)list; (void)hashtag; (void)is_private;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_list_add_word(nostr_list* list, const char* word, bool is_private)
{
    (void)list; (void)word; (void)is_private;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_list_add_relay(nostr_list* list, const char* relay_url, bool is_private)
{
    (void)list; (void)relay_url; (void)is_private;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_list_add_reference(nostr_list* list, const char* reference,
                                       const char* relay_hint, bool is_private)
{
    (void)list; (void)reference; (void)relay_hint; (void)is_private;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_list_add_group(nostr_list* list, const char* group_id,
                                   const char* relay_url, const char* group_name, bool is_private)
{
    (void)list; (void)group_id; (void)relay_url; (void)group_name; (void)is_private;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_list_add_emoji(nostr_list* list, const char* shortcode,
                                   const char* image_url, bool is_private)
{
    (void)list; (void)shortcode; (void)image_url; (void)is_private;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_list_to_event(const nostr_list* list, const nostr_keypair* keypair,
                                  nostr_event** event)
{
    (void)list; (void)keypair; (void)event;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_list_from_event(const nostr_event* event, const nostr_keypair* keypair,
                                    nostr_list** list)
{
    (void)event; (void)keypair; (void)list;
    return NOSTR_ERR_NOT_SUPPORTED;
}

size_t nostr_list_count(const nostr_list* list)
{
    (void)list;
    return 0;
}

const nostr_list_item* nostr_list_get(const nostr_list* list, size_t index)
{
    (void)list; (void)index;
    return NULL;
}

nostr_error_t nostr_list_remove(nostr_list* list, size_t index)
{
    (void)list; (void)index;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif
