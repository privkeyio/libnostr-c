#ifdef HAVE_UNITY
#include "unity.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/nostr.h"
#include "../include/nostr_features.h"

#ifdef NOSTR_FEATURE_NIP18

#define TEST_EVENT_ID "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
#define TEST_PUBKEY   "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"
#define TEST_RELAY    "wss://relay.example.com"

#ifndef HAVE_UNITY
#define TEST_ASSERT_EQUAL(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("Assertion failed: %s != %s\n", #expected, #actual); \
            return; \
        } \
    } while(0)

#define TEST_ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            printf("Pointer is NULL: %s\n", #ptr); \
            return; \
        } \
    } while(0)

#define TEST_ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            printf("Condition failed: %s\n", #condition); \
            return; \
        } \
    } while(0)

#define TEST_ASSERT_EQUAL_STRING(expected, actual) \
    do { \
        if (strcmp(expected, actual) != 0) { \
            printf("String comparison failed: %s != %s\n", expected, actual); \
            return; \
        } \
    } while(0)
#endif

static void test_repost_create_kind1(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_repost_create(&event, TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 1, NULL);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL(6, event->kind);
    TEST_ASSERT_EQUAL_STRING("", event->content);

    int found_e = 0, found_p = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2) {
            if (strcmp(event->tags[i].values[0], "e") == 0) {
                found_e = 1;
                TEST_ASSERT_EQUAL_STRING(TEST_EVENT_ID, event->tags[i].values[1]);
                TEST_ASSERT_TRUE(event->tags[i].count >= 3);
                TEST_ASSERT_EQUAL_STRING(TEST_RELAY, event->tags[i].values[2]);
            } else if (strcmp(event->tags[i].values[0], "p") == 0) {
                found_p = 1;
                TEST_ASSERT_EQUAL_STRING(TEST_PUBKEY, event->tags[i].values[1]);
            }
        }
    }

    TEST_ASSERT_TRUE(found_e);
    TEST_ASSERT_TRUE(found_p);

    nostr_event_destroy(event);
}

static void test_repost_create_generic(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_repost_create(&event, TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 30023, NULL);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL(16, event->kind);

    int found_k = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2) {
            if (strcmp(event->tags[i].values[0], "k") == 0) {
                found_k = 1;
                TEST_ASSERT_EQUAL_STRING("30023", event->tags[i].values[1]);
            }
        }
    }

    TEST_ASSERT_TRUE(found_k);

    nostr_event_destroy(event);
}

static void test_repost_create_with_embedded_json(void)
{
    const char* embedded = "{\"id\":\"test\",\"content\":\"hello\"}";
    nostr_event* event = NULL;
    nostr_error_t err = nostr_repost_create(&event, TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 1, embedded);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL_STRING(embedded, event->content);

    nostr_event_destroy(event);
}

static void test_repost_parse_kind6(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_repost_create(&event, TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 1, NULL);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    char event_id[65];
    char pubkey[65];
    char relay[256];
    uint16_t kind = 0;

    err = nostr_repost_parse(event, event_id, sizeof(event_id), pubkey, sizeof(pubkey),
                             relay, sizeof(relay), &kind);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL_STRING(TEST_EVENT_ID, event_id);
    TEST_ASSERT_EQUAL_STRING(TEST_PUBKEY, pubkey);
    TEST_ASSERT_EQUAL_STRING(TEST_RELAY, relay);
    TEST_ASSERT_EQUAL(1, kind);

    nostr_event_destroy(event);
}

static void test_repost_parse_kind16(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_repost_create(&event, TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 7, NULL);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    char event_id[65];
    char pubkey[65];
    uint16_t kind = 0;

    err = nostr_repost_parse(event, event_id, sizeof(event_id), pubkey, sizeof(pubkey),
                             NULL, 0, &kind);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL_STRING(TEST_EVENT_ID, event_id);
    TEST_ASSERT_EQUAL_STRING(TEST_PUBKEY, pubkey);
    TEST_ASSERT_EQUAL(7, kind);

    nostr_event_destroy(event);
}

static void test_repost_parse_invalid_kind(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    event->kind = 1;

    char event_id[65];
    err = nostr_repost_parse(event, event_id, sizeof(event_id), NULL, 0, NULL, 0, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, err);

    nostr_event_destroy(event);
}

static void test_invalid_params(void)
{
    nostr_error_t err;

    err = nostr_repost_create(NULL, TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 1, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    nostr_event* event = NULL;
    err = nostr_repost_create(&event, NULL, TEST_PUBKEY, TEST_RELAY, 1, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_repost_create(&event, TEST_EVENT_ID, NULL, TEST_RELAY, 1, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_repost_create(&event, TEST_EVENT_ID, TEST_PUBKEY, NULL, 1, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_repost_create(&event, "invalid", TEST_PUBKEY, TEST_RELAY, 1, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_repost_parse(NULL, NULL, 0, NULL, 0, NULL, 0, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);
}

void run_nip18_tests(void)
{
    printf("   Running NIP-18 tests...\n");

    test_repost_create_kind1();
    printf("     Success: test_repost_create_kind1\n");

    test_repost_create_generic();
    printf("     Success: test_repost_create_generic\n");

    test_repost_create_with_embedded_json();
    printf("     Success: test_repost_create_with_embedded_json\n");

    test_repost_parse_kind6();
    printf("     Success: test_repost_parse_kind6\n");

    test_repost_parse_kind16();
    printf("     Success: test_repost_parse_kind16\n");

    test_repost_parse_invalid_kind();
    printf("     Success: test_repost_parse_invalid_kind\n");

    test_invalid_params();
    printf("     Success: test_invalid_params\n");
}

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    printf("Running NIP-18 tests...\n\n");
    run_nip18_tests();
    printf("\nAll NIP-18 tests completed!\n");
    return 0;
}
#endif

#else

void run_nip18_tests(void)
{
    printf("   NIP-18 tests skipped (NIP-18 not enabled)\n");
}

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    printf("NIP-18 not enabled in build\n");
    return 0;
}
#endif

#endif
