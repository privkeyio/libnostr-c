#include "nostr.h"

#ifdef NOSTR_FEATURE_NIP65

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define KIND_RELAY_LIST 10002
#define INITIAL_RELAY_CAPACITY 8
#define MAX_RELAY_COUNT 256
#define MAX_URL_LENGTH 2048

static void cleanup_event(nostr_event** event)
{
    nostr_event_destroy(*event);
    *event = NULL;
}

nostr_error_t nostr_relay_list_create(nostr_relay_list** list)
{
    if (!list) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    *list = calloc(1, sizeof(nostr_relay_list));
    if (!*list) {
        return NOSTR_ERR_MEMORY;
    }

    (*list)->relays = calloc(INITIAL_RELAY_CAPACITY, sizeof(nostr_relay_list_entry));
    if (!(*list)->relays) {
        free(*list);
        *list = NULL;
        return NOSTR_ERR_MEMORY;
    }

    (*list)->capacity = INITIAL_RELAY_CAPACITY;
    (*list)->count = 0;

    return NOSTR_OK;
}

void nostr_relay_list_free(nostr_relay_list* list)
{
    if (!list) {
        return;
    }

    for (size_t i = 0; i < list->count; i++) {
        free(list->relays[i].url);
    }
    free(list->relays);
    free(list);
}

static bool is_valid_relay_url(const char* url)
{
    if (!url) {
        return false;
    }
    size_t len = strlen(url);
    if (len == 0 || len > MAX_URL_LENGTH) {
        return false;
    }

    size_t prefix_len;
    if (strncmp(url, "wss://", 6) == 0) {
        prefix_len = 6;
    } else if (strncmp(url, "ws://", 5) == 0) {
        prefix_len = 5;
    } else {
        return false;
    }

    if (len <= prefix_len) {
        return false;
    }

    char first_host_char = url[prefix_len];
    if (first_host_char == '/' || first_host_char == ':' || first_host_char == '?' ||
        first_host_char == '#' || first_host_char == '@' || first_host_char == ' ') {
        return false;
    }

    return true;
}

nostr_error_t nostr_relay_list_add(nostr_relay_list* list, const char* url, bool read, bool write)
{
    if (!list || !url || (!read && !write)) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (!is_valid_relay_url(url)) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (list->count >= MAX_RELAY_COUNT) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->relays[i].url, url) == 0) {
            return NOSTR_ERR_INVALID_PARAM;
        }
    }

    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity * 2;
        if (new_capacity < list->capacity || new_capacity > MAX_RELAY_COUNT) {
            new_capacity = MAX_RELAY_COUNT;
        }
        if (new_capacity <= list->count) {
            return NOSTR_ERR_MEMORY;
        }
        size_t alloc_size = new_capacity * sizeof(nostr_relay_list_entry);
        if (alloc_size / sizeof(nostr_relay_list_entry) != new_capacity) {
            return NOSTR_ERR_MEMORY;
        }
        nostr_relay_list_entry* new_relays = realloc(list->relays, alloc_size);
        if (!new_relays) {
            return NOSTR_ERR_MEMORY;
        }
        memset(&new_relays[list->capacity], 0,
               (new_capacity - list->capacity) * sizeof(nostr_relay_list_entry));
        list->relays = new_relays;
        list->capacity = new_capacity;
    }

    list->relays[list->count].url = strdup(url);
    if (!list->relays[list->count].url) {
        return NOSTR_ERR_MEMORY;
    }

    list->relays[list->count].read = read;
    list->relays[list->count].write = write;
    list->count++;

    return NOSTR_OK;
}

nostr_error_t nostr_relay_list_to_event(const nostr_relay_list* list, nostr_event** event)
{
    if (!list || !event) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    nostr_error_t err = nostr_event_create(event);
    if (err != NOSTR_OK) {
        return err;
    }

    (*event)->kind = KIND_RELAY_LIST;
    (*event)->created_at = time(NULL);

    err = nostr_event_set_content(*event, "");
    if (err != NOSTR_OK) {
        cleanup_event(event);
        return err;
    }

    for (size_t i = 0; i < list->count; i++) {
        const nostr_relay_list_entry* entry = &list->relays[i];
        const char* tag_values[3] = {"r", entry->url, NULL};
        size_t tag_count = 2;

        if (!entry->read || !entry->write) {
            tag_values[2] = entry->read ? "read" : "write";
            tag_count = 3;
        }

        err = nostr_event_add_tag(*event, tag_values, tag_count);
        if (err != NOSTR_OK) {
            cleanup_event(event);
            return err;
        }
    }

    return NOSTR_OK;
}

nostr_error_t nostr_relay_list_from_event(const nostr_event* event, nostr_relay_list** list)
{
    if (!event || !list) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (event->kind != KIND_RELAY_LIST) {
        return NOSTR_ERR_INVALID_EVENT;
    }

    nostr_error_t err = nostr_relay_list_create(list);
    if (err != NOSTR_OK) {
        return err;
    }

    for (size_t i = 0; i < event->tags_count; i++) {
        const nostr_tag* tag = &event->tags[i];

        if (tag->count < 2 || !tag->values || !tag->values[0] || !tag->values[1]) {
            continue;
        }

        if (strcmp(tag->values[0], "r") != 0) {
            continue;
        }

        const char* url = tag->values[1];
        bool read = true;
        bool write = true;

        if (tag->count >= 3 && tag->values[2]) {
            const char* marker = tag->values[2];
            if (strcmp(marker, "read") == 0) {
                write = false;
            } else if (strcmp(marker, "write") == 0) {
                read = false;
            }
        }

        err = nostr_relay_list_add(*list, url, read, write);
        if (err == NOSTR_ERR_MEMORY) {
            nostr_relay_list_free(*list);
            *list = NULL;
            return err;
        }
    }

    return NOSTR_OK;
}

size_t nostr_relay_list_count(const nostr_relay_list* list)
{
    if (!list) {
        return 0;
    }
    return list->count;
}

const nostr_relay_list_entry* nostr_relay_list_get(const nostr_relay_list* list, size_t index)
{
    if (!list || index >= list->count) {
        return NULL;
    }
    return &list->relays[index];
}

static nostr_error_t get_relays_by_flag(const nostr_relay_list* list, bool for_read,
                                         char*** urls, size_t* count)
{
    if (!list || !urls || !count) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    size_t match_count = 0;
    for (size_t i = 0; i < list->count; i++) {
        bool match = for_read ? list->relays[i].read : list->relays[i].write;
        if (match) {
            match_count++;
        }
    }

    if (match_count == 0) {
        *urls = NULL;
        *count = 0;
        return NOSTR_OK;
    }

    *urls = calloc(match_count, sizeof(char*));
    if (!*urls) {
        return NOSTR_ERR_MEMORY;
    }

    size_t j = 0;
    for (size_t i = 0; i < list->count && j < match_count; i++) {
        bool match = for_read ? list->relays[i].read : list->relays[i].write;
        if (match) {
            (*urls)[j] = strdup(list->relays[i].url);
            if (!(*urls)[j]) {
                for (size_t k = 0; k < j; k++) {
                    free((*urls)[k]);
                }
                free(*urls);
                *urls = NULL;
                return NOSTR_ERR_MEMORY;
            }
            j++;
        }
    }

    *count = match_count;
    return NOSTR_OK;
}

nostr_error_t nostr_relay_list_get_read_relays(const nostr_relay_list* list,
                                                char*** urls, size_t* count)
{
    return get_relays_by_flag(list, true, urls, count);
}

nostr_error_t nostr_relay_list_get_write_relays(const nostr_relay_list* list,
                                                 char*** urls, size_t* count)
{
    return get_relays_by_flag(list, false, urls, count);
}

void nostr_relay_list_free_urls(char** urls, size_t count)
{
    if (!urls) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(urls[i]);
    }
    free(urls);
}

#else

nostr_error_t nostr_relay_list_create(nostr_relay_list** list)
{
    (void)list;
    return NOSTR_ERR_NOT_SUPPORTED;
}

void nostr_relay_list_free(nostr_relay_list* list)
{
    (void)list;
}

nostr_error_t nostr_relay_list_add(nostr_relay_list* list, const char* url, bool read, bool write)
{
    (void)list; (void)url; (void)read; (void)write;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_relay_list_to_event(const nostr_relay_list* list, nostr_event** event)
{
    (void)list; (void)event;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_relay_list_from_event(const nostr_event* event, nostr_relay_list** list)
{
    (void)event; (void)list;
    return NOSTR_ERR_NOT_SUPPORTED;
}

size_t nostr_relay_list_count(const nostr_relay_list* list)
{
    (void)list;
    return 0;
}

const nostr_relay_list_entry* nostr_relay_list_get(const nostr_relay_list* list, size_t index)
{
    (void)list; (void)index;
    return NULL;
}

nostr_error_t nostr_relay_list_get_read_relays(const nostr_relay_list* list,
                                                char*** urls, size_t* count)
{
    (void)list; (void)urls; (void)count;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_relay_list_get_write_relays(const nostr_relay_list* list,
                                                 char*** urls, size_t* count)
{
    (void)list; (void)urls; (void)count;
    return NOSTR_ERR_NOT_SUPPORTED;
}

void nostr_relay_list_free_urls(char** urls, size_t count)
{
    (void)urls; (void)count;
}

#endif
