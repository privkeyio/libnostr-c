#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/nostr.h"
#include "../include/nostr_features.h"

#define TEST_ASSERT_EQUAL(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("FAIL: %s != %s at line %d\n", #expected, #actual, __LINE__); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            printf("FAIL: %s is NULL at line %d\n", #ptr, __LINE__); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_NULL(ptr) \
    do { \
        if ((ptr) != NULL) { \
            printf("FAIL: %s is not NULL at line %d\n", #ptr, __LINE__); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            printf("FAIL: %s at line %d\n", #condition, __LINE__); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_EQUAL_STRING(expected, actual) \
    do { \
        if (strcmp(expected, actual) != 0) { \
            printf("FAIL: \"%s\" != \"%s\" at line %d\n", expected, actual, __LINE__); \
            return 1; \
        } \
    } while(0)

#define RUN_TEST(test_func) \
    do { \
        printf(#test_func ": "); \
        if (test_func() == 0) { \
            printf("PASS\n"); \
        } else { \
            failures++; \
        } \
    } while(0)

static int test_relay_list_create_free(void)
{
    nostr_relay_list* list = NULL;

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_list_create(&list));
    TEST_ASSERT_NOT_NULL(list);
    TEST_ASSERT_EQUAL(0, nostr_relay_list_count(list));

    nostr_relay_list_free(list);
    return 0;
}

static int test_relay_list_create_invalid(void)
{
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_relay_list_create(NULL));
    return 0;
}

static int test_relay_list_add(void)
{
    nostr_relay_list* list = NULL;
    nostr_relay_list_create(&list);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_list_add(list, "wss://relay1.example.com", true, true));
    TEST_ASSERT_EQUAL(1, nostr_relay_list_count(list));

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_list_add(list, "wss://relay2.example.com", true, false));
    TEST_ASSERT_EQUAL(2, nostr_relay_list_count(list));

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_list_add(list, "wss://relay3.example.com", false, true));
    TEST_ASSERT_EQUAL(3, nostr_relay_list_count(list));

    const nostr_relay_list_entry* entry = nostr_relay_list_get(list, 0);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL_STRING("wss://relay1.example.com", entry->url);
    TEST_ASSERT_TRUE(entry->read);
    TEST_ASSERT_TRUE(entry->write);

    entry = nostr_relay_list_get(list, 1);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL_STRING("wss://relay2.example.com", entry->url);
    TEST_ASSERT_TRUE(entry->read);
    TEST_ASSERT_TRUE(!entry->write);

    entry = nostr_relay_list_get(list, 2);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL_STRING("wss://relay3.example.com", entry->url);
    TEST_ASSERT_TRUE(!entry->read);
    TEST_ASSERT_TRUE(entry->write);

    nostr_relay_list_free(list);
    return 0;
}

static int test_relay_list_add_invalid(void)
{
    nostr_relay_list* list = NULL;
    nostr_relay_list_create(&list);

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_relay_list_add(NULL, "wss://example.com", true, true));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_relay_list_add(list, NULL, true, true));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_relay_list_add(list, "wss://example.com", false, false));

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_relay_list_add(list, "", true, true));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_relay_list_add(list, "http://example.com", true, true));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_relay_list_add(list, "https://example.com", true, true));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_relay_list_add(list, "example.com", true, true));

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_list_add(list, "ws://example.com", true, true));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_list_add(list, "wss://example.com", true, true));

    nostr_relay_list_free(list);
    return 0;
}

static int test_relay_list_to_event(void)
{
    nostr_relay_list* list = NULL;
    nostr_event* event = NULL;

    nostr_relay_list_create(&list);
    nostr_relay_list_add(list, "wss://relay1.example.com", true, true);
    nostr_relay_list_add(list, "wss://relay2.example.com", true, false);
    nostr_relay_list_add(list, "wss://relay3.example.com", false, true);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_list_to_event(list, &event));
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL(10002, event->kind);
    TEST_ASSERT_EQUAL(3, event->tags_count);

    TEST_ASSERT_EQUAL_STRING("r", event->tags[0].values[0]);
    TEST_ASSERT_EQUAL_STRING("wss://relay1.example.com", event->tags[0].values[1]);
    TEST_ASSERT_EQUAL(2, event->tags[0].count);

    TEST_ASSERT_EQUAL_STRING("r", event->tags[1].values[0]);
    TEST_ASSERT_EQUAL_STRING("wss://relay2.example.com", event->tags[1].values[1]);
    TEST_ASSERT_EQUAL_STRING("read", event->tags[1].values[2]);
    TEST_ASSERT_EQUAL(3, event->tags[1].count);

    TEST_ASSERT_EQUAL_STRING("r", event->tags[2].values[0]);
    TEST_ASSERT_EQUAL_STRING("wss://relay3.example.com", event->tags[2].values[1]);
    TEST_ASSERT_EQUAL_STRING("write", event->tags[2].values[2]);
    TEST_ASSERT_EQUAL(3, event->tags[2].count);

    nostr_event_destroy(event);
    nostr_relay_list_free(list);
    return 0;
}

static int test_relay_list_from_event(void)
{
    nostr_relay_list* original = NULL;
    nostr_event* event = NULL;
    nostr_relay_list* parsed = NULL;

    nostr_relay_list_create(&original);
    nostr_relay_list_add(original, "wss://relay1.example.com", true, true);
    nostr_relay_list_add(original, "wss://relay2.example.com", true, false);
    nostr_relay_list_add(original, "wss://relay3.example.com", false, true);

    nostr_relay_list_to_event(original, &event);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_list_from_event(event, &parsed));
    TEST_ASSERT_NOT_NULL(parsed);
    TEST_ASSERT_EQUAL(3, nostr_relay_list_count(parsed));

    const nostr_relay_list_entry* entry = nostr_relay_list_get(parsed, 0);
    TEST_ASSERT_EQUAL_STRING("wss://relay1.example.com", entry->url);
    TEST_ASSERT_TRUE(entry->read);
    TEST_ASSERT_TRUE(entry->write);

    entry = nostr_relay_list_get(parsed, 1);
    TEST_ASSERT_EQUAL_STRING("wss://relay2.example.com", entry->url);
    TEST_ASSERT_TRUE(entry->read);
    TEST_ASSERT_TRUE(!entry->write);

    entry = nostr_relay_list_get(parsed, 2);
    TEST_ASSERT_EQUAL_STRING("wss://relay3.example.com", entry->url);
    TEST_ASSERT_TRUE(!entry->read);
    TEST_ASSERT_TRUE(entry->write);

    nostr_relay_list_free(parsed);
    nostr_event_destroy(event);
    nostr_relay_list_free(original);
    return 0;
}

static int test_relay_list_from_event_invalid_kind(void)
{
    nostr_event* event = NULL;
    nostr_relay_list* list = NULL;

    nostr_event_create(&event);
    event->kind = 1;

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, nostr_relay_list_from_event(event, &list));
    TEST_ASSERT_NULL(list);

    nostr_event_destroy(event);
    return 0;
}

static int test_relay_list_get_read_relays(void)
{
    nostr_relay_list* list = NULL;
    char** urls = NULL;
    size_t count = 0;

    nostr_relay_list_create(&list);
    nostr_relay_list_add(list, "wss://relay1.example.com", true, true);
    nostr_relay_list_add(list, "wss://relay2.example.com", true, false);
    nostr_relay_list_add(list, "wss://relay3.example.com", false, true);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_list_get_read_relays(list, &urls, &count));
    TEST_ASSERT_EQUAL(2, count);
    TEST_ASSERT_NOT_NULL(urls);
    TEST_ASSERT_EQUAL_STRING("wss://relay1.example.com", urls[0]);
    TEST_ASSERT_EQUAL_STRING("wss://relay2.example.com", urls[1]);

    nostr_relay_list_free_urls(urls, count);
    nostr_relay_list_free(list);
    return 0;
}

static int test_relay_list_get_write_relays(void)
{
    nostr_relay_list* list = NULL;
    char** urls = NULL;
    size_t count = 0;

    nostr_relay_list_create(&list);
    nostr_relay_list_add(list, "wss://relay1.example.com", true, true);
    nostr_relay_list_add(list, "wss://relay2.example.com", true, false);
    nostr_relay_list_add(list, "wss://relay3.example.com", false, true);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_list_get_write_relays(list, &urls, &count));
    TEST_ASSERT_EQUAL(2, count);
    TEST_ASSERT_NOT_NULL(urls);
    TEST_ASSERT_EQUAL_STRING("wss://relay1.example.com", urls[0]);
    TEST_ASSERT_EQUAL_STRING("wss://relay3.example.com", urls[1]);

    nostr_relay_list_free_urls(urls, count);
    nostr_relay_list_free(list);
    return 0;
}

static int test_relay_list_get_out_of_bounds(void)
{
    nostr_relay_list* list = NULL;
    nostr_relay_list_create(&list);
    nostr_relay_list_add(list, "wss://relay.example.com", true, true);

    TEST_ASSERT_NULL(nostr_relay_list_get(list, 1));
    TEST_ASSERT_NULL(nostr_relay_list_get(list, 100));
    TEST_ASSERT_NULL(nostr_relay_list_get(NULL, 0));

    nostr_relay_list_free(list);
    return 0;
}

static int test_relay_list_capacity_growth(void)
{
    nostr_relay_list* list = NULL;
    nostr_relay_list_create(&list);

    for (int i = 0; i < 20; i++) {
        char url[64];
        snprintf(url, sizeof(url), "wss://relay%d.example.com", i);
        TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_list_add(list, url, true, true));
    }

    TEST_ASSERT_EQUAL(20, nostr_relay_list_count(list));

    for (int i = 0; i < 20; i++) {
        char expected_url[64];
        snprintf(expected_url, sizeof(expected_url), "wss://relay%d.example.com", i);
        const nostr_relay_list_entry* entry = nostr_relay_list_get(list, i);
        TEST_ASSERT_NOT_NULL(entry);
        TEST_ASSERT_EQUAL_STRING(expected_url, entry->url);
    }

    nostr_relay_list_free(list);
    return 0;
}

int main(void)
{
    int failures = 0;

#ifdef NOSTR_FEATURE_NIP65
    printf("Running NIP-65 tests...\n\n");

    RUN_TEST(test_relay_list_create_free);
    RUN_TEST(test_relay_list_create_invalid);
    RUN_TEST(test_relay_list_add);
    RUN_TEST(test_relay_list_add_invalid);
    RUN_TEST(test_relay_list_to_event);
    RUN_TEST(test_relay_list_from_event);
    RUN_TEST(test_relay_list_from_event_invalid_kind);
    RUN_TEST(test_relay_list_get_read_relays);
    RUN_TEST(test_relay_list_get_write_relays);
    RUN_TEST(test_relay_list_get_out_of_bounds);
    RUN_TEST(test_relay_list_capacity_growth);

    printf("\n");
    if (failures == 0) {
        printf("All NIP-65 tests passed!\n");
    } else {
        printf("%d test(s) failed.\n", failures);
    }
#else
    printf("NIP-65 not enabled, skipping tests.\n");
#endif

    return failures;
}
