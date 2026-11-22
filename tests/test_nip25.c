#include "unity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/nostr.h"
#include "../include/nostr_features.h"

#ifdef NOSTR_FEATURE_NIP25

#define TEST_EVENT_ID "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
#define TEST_PUBKEY   "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"
#define TEST_RELAY    "wss://relay.example.com"

static void test_reaction_create_like(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_reaction_create(&event, "+", TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 1);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL(7, event->kind);
    TEST_ASSERT_EQUAL_STRING("+", event->content);

    int found_e = 0, found_p = 0, found_k = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2) {
            if (strcmp(event->tags[i].values[0], "e") == 0) {
                found_e = 1;
                TEST_ASSERT_EQUAL_STRING(TEST_EVENT_ID, event->tags[i].values[1]);
            } else if (strcmp(event->tags[i].values[0], "p") == 0) {
                found_p = 1;
                TEST_ASSERT_EQUAL_STRING(TEST_PUBKEY, event->tags[i].values[1]);
            } else if (strcmp(event->tags[i].values[0], "k") == 0) {
                found_k = 1;
                TEST_ASSERT_EQUAL_STRING("1", event->tags[i].values[1]);
            }
        }
    }

    TEST_ASSERT_TRUE(found_e);
    TEST_ASSERT_TRUE(found_p);
    TEST_ASSERT_TRUE(found_k);

    nostr_event_destroy(event);
}

static void test_reaction_create_dislike(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_reaction_create(&event, "-", TEST_EVENT_ID, TEST_PUBKEY, NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL(7, event->kind);
    TEST_ASSERT_EQUAL_STRING("-", event->content);

    nostr_event_destroy(event);
}

static void test_reaction_create_emoji(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_reaction_create(&event, "\xF0\x9F\x94\xA5", TEST_EVENT_ID, TEST_PUBKEY, NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL_STRING("\xF0\x9F\x94\xA5", event->content);

    nostr_event_destroy(event);
}

static void test_reaction_create_default(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_reaction_create(&event, NULL, TEST_EVENT_ID, TEST_PUBKEY, NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL_STRING("+", event->content);

    nostr_event_destroy(event);
}

static void test_reaction_parse(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_reaction_create(&event, "+", TEST_EVENT_ID, TEST_PUBKEY, TEST_RELAY, 1);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    char content[32];
    char event_id[65];
    char pubkey[65];
    uint16_t kind = 0;

    err = nostr_reaction_parse(event, content, sizeof(content), event_id, sizeof(event_id),
                               pubkey, sizeof(pubkey), &kind);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL_STRING("+", content);
    TEST_ASSERT_EQUAL_STRING(TEST_EVENT_ID, event_id);
    TEST_ASSERT_EQUAL_STRING(TEST_PUBKEY, pubkey);
    TEST_ASSERT_EQUAL(1, kind);

    nostr_event_destroy(event);
}

static void test_reaction_is_like(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_reaction_create(&event, "+", TEST_EVENT_ID, TEST_PUBKEY, NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    int is_like = 0;
    err = nostr_reaction_is_like(event, &is_like);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL(1, is_like);

    nostr_event_destroy(event);
}

static void test_reaction_is_like_empty(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_reaction_create(&event, "", TEST_EVENT_ID, TEST_PUBKEY, NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    int is_like = 0;
    err = nostr_reaction_is_like(event, &is_like);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL(1, is_like);

    nostr_event_destroy(event);
}

static void test_reaction_is_dislike(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_reaction_create(&event, "-", TEST_EVENT_ID, TEST_PUBKEY, NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    int is_dislike = 0;
    err = nostr_reaction_is_dislike(event, &is_dislike);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL(1, is_dislike);

    int is_like = 0;
    err = nostr_reaction_is_like(event, &is_like);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL(0, is_like);

    nostr_event_destroy(event);
}

static void test_reaction_emoji_not_like(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_reaction_create(&event, "\xF0\x9F\x94\xA5", TEST_EVENT_ID, TEST_PUBKEY, NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    int is_like = 0;
    err = nostr_reaction_is_like(event, &is_like);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL(0, is_like);

    int is_dislike = 0;
    err = nostr_reaction_is_dislike(event, &is_dislike);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL(0, is_dislike);

    nostr_event_destroy(event);
}

static void test_reaction_parse_invalid_kind(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    event->kind = 1;

    char content[32];
    err = nostr_reaction_parse(event, content, sizeof(content), NULL, 0, NULL, 0, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, err);

    nostr_event_destroy(event);
}

static void test_invalid_params(void)
{
    nostr_error_t err;

    err = nostr_reaction_create(NULL, "+", "id", "pk", NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    nostr_event* event = NULL;
    err = nostr_reaction_create(&event, "+", NULL, "pk", NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_reaction_create(&event, "+", "id", NULL, NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_reaction_parse(NULL, NULL, 0, NULL, 0, NULL, 0, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_reaction_is_like(NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_reaction_is_dislike(NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);
}

void run_nip25_tests(void)
{
    printf("   Running NIP-25 tests...\n");

    RUN_TEST(test_reaction_create_like);
    RUN_TEST(test_reaction_create_dislike);
    RUN_TEST(test_reaction_create_emoji);
    RUN_TEST(test_reaction_create_default);
    RUN_TEST(test_reaction_parse);
    RUN_TEST(test_reaction_is_like);
    RUN_TEST(test_reaction_is_like_empty);
    RUN_TEST(test_reaction_is_dislike);
    RUN_TEST(test_reaction_emoji_not_like);
    RUN_TEST(test_reaction_parse_invalid_kind);
    RUN_TEST(test_invalid_params);
}

#ifndef TEST_RUNNER_INCLUDED
void setUp(void) {}
void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    run_nip25_tests();
    return UNITY_END();
}
#endif

#else

void run_nip25_tests(void)
{
    printf("   NIP-25 tests skipped (NIP-25 not enabled)\n");
}

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    printf("NIP-25 not enabled in build\n");
    return 0;
}
#endif

#endif
