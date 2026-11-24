#include "unity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/nostr.h"
#include "../include/nostr_features.h"

#ifdef NOSTR_FEATURE_NIP18

#define TEST_EVENT_ID "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
#define TEST_PUBKEY   "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"
#define TEST_RELAY    "wss://relay.example.com"

static void test_repost_create_kind1(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_repost_create(&event, TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 1, NULL, NULL);
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
    nostr_error_t err = nostr_repost_create(&event, TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 30023, NULL, NULL);
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
    nostr_error_t err = nostr_repost_create(&event, TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 1, NULL, embedded);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL_STRING(embedded, event->content);

    nostr_event_destroy(event);
}

static void test_repost_create_with_a_tag(void)
{
    nostr_event* event = NULL;
    const char* d_tag = "my-article";
    nostr_error_t err = nostr_repost_create(&event, TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 30023, d_tag, NULL);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL(16, event->kind);

    int found_a = 0, found_k = 0;
    char expected_a[256];
    snprintf(expected_a, sizeof(expected_a), "30023:%s:%s", TEST_PUBKEY, d_tag);

    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2) {
            if (strcmp(event->tags[i].values[0], "a") == 0) {
                found_a = 1;
                TEST_ASSERT_EQUAL_STRING(expected_a, event->tags[i].values[1]);
            } else if (strcmp(event->tags[i].values[0], "k") == 0) {
                found_k = 1;
                TEST_ASSERT_EQUAL_STRING("30023", event->tags[i].values[1]);
            }
        }
    }

    TEST_ASSERT_TRUE(found_a);
    TEST_ASSERT_TRUE(found_k);

    nostr_event_destroy(event);
}

static void test_repost_parse_kind6(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_repost_create(&event, TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 1, NULL, NULL);
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
    nostr_error_t err = nostr_repost_create(&event, TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 7, NULL, NULL);
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

    err = nostr_repost_create(NULL, TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 1, NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    nostr_event* event = NULL;
    err = nostr_repost_create(&event, NULL, TEST_PUBKEY, TEST_RELAY, 1, NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_repost_create(&event, TEST_EVENT_ID, NULL, TEST_RELAY, 1, NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_repost_create(&event, TEST_EVENT_ID, TEST_PUBKEY, NULL, 1, NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_repost_create(&event, "invalid", TEST_PUBKEY, TEST_RELAY, 1, NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_repost_parse(NULL, NULL, 0, NULL, 0, NULL, 0, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);
}

static void test_quote_tags_note(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_event_set_content(event, "Check this out nostr:note1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqn2l0z3");
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_quote_tags_from_content(event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    int found_q = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 && strcmp(event->tags[i].values[0], "q") == 0) {
            found_q = 1;
            TEST_ASSERT_TRUE(strlen(event->tags[i].values[1]) == 64);
            TEST_ASSERT_EQUAL(4, event->tags[i].count);
            TEST_ASSERT_EQUAL_STRING("", event->tags[i].values[2]);
            TEST_ASSERT_EQUAL_STRING("", event->tags[i].values[3]);
        }
    }
    TEST_ASSERT_TRUE(found_q);

    nostr_event_destroy(event);
}

static void test_quote_tags_nevent(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_event_set_content(event,
        "Look at nostr:nevent1qqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqradspk");
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_quote_tags_from_content(event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    int found_q = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 && strcmp(event->tags[i].values[0], "q") == 0) {
            found_q = 1;
            TEST_ASSERT_TRUE(strlen(event->tags[i].values[1]) == 64);
            TEST_ASSERT_EQUAL(4, event->tags[i].count);
        }
    }
    TEST_ASSERT_TRUE(found_q);

    nostr_event_destroy(event);
}

static void test_quote_tags_multiple_mentions(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_event_set_content(event,
        "First nostr:note1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqn2l0z3 "
        "and second nostr:note1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqn2l0z3");
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_quote_tags_from_content(event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    int q_count = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 && strcmp(event->tags[i].values[0], "q") == 0)
            q_count++;
    }
    TEST_ASSERT_EQUAL(2, q_count);

    nostr_event_destroy(event);
}

static void test_quote_tags_no_mentions(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_event_set_content(event, "Just a regular post with no mentions.");
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_quote_tags_from_content(event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    int q_count = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 && strcmp(event->tags[i].values[0], "q") == 0)
            q_count++;
    }
    TEST_ASSERT_EQUAL(0, q_count);

    nostr_event_destroy(event);
}

static void test_quote_tags_empty_content(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_event_set_content(event, "");
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_quote_tags_from_content(event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL(0, event->tags_count);

    nostr_event_destroy(event);
}

static void test_quote_tags_null_event(void)
{
    nostr_error_t err = nostr_quote_tags_from_content(NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);
}

static void test_quote_tags_nevent_with_relay_and_author(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_event_set_content(event,
        "Look at nostr:nevent1qqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgzyz4242424242424242424242424242424242424242424242424254gvmty");
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_quote_tags_from_content(event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    int found_q = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 && strcmp(event->tags[i].values[0], "q") == 0) {
            found_q = 1;
            TEST_ASSERT_EQUAL(4, event->tags[i].count);
            TEST_ASSERT_TRUE(strlen(event->tags[i].values[1]) == 64);
            TEST_ASSERT_EQUAL_STRING("wss://relay.example.com", event->tags[i].values[2]);
            TEST_ASSERT_TRUE(strlen(event->tags[i].values[3]) == 64);
        }
    }
    TEST_ASSERT_TRUE(found_q);

    nostr_event_destroy(event);
}

void run_nip18_tests(void)
{
    printf("   Running NIP-18 tests...\n");

    RUN_TEST(test_repost_create_kind1);
    RUN_TEST(test_repost_create_generic);
    RUN_TEST(test_repost_create_with_embedded_json);
    RUN_TEST(test_repost_create_with_a_tag);
    RUN_TEST(test_repost_parse_kind6);
    RUN_TEST(test_repost_parse_kind16);
    RUN_TEST(test_repost_parse_invalid_kind);
    RUN_TEST(test_invalid_params);
    RUN_TEST(test_quote_tags_note);
    RUN_TEST(test_quote_tags_nevent);
    RUN_TEST(test_quote_tags_multiple_mentions);
    RUN_TEST(test_quote_tags_no_mentions);
    RUN_TEST(test_quote_tags_empty_content);
    RUN_TEST(test_quote_tags_null_event);
    RUN_TEST(test_quote_tags_nevent_with_relay_and_author);
}

#ifndef TEST_RUNNER_INCLUDED
void setUp(void) {}
void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    run_nip18_tests();
    return UNITY_END();
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
