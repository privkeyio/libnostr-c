#ifdef HAVE_UNITY
#include "unity.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/nostr.h"
#include "../include/nostr_features.h"

#ifdef NOSTR_FEATURE_NIP10

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

static void test_get_root_id_marked(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    const char* root_tag[] = {"e", "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", "wss://relay.example.com", "root"};
    err = nostr_event_add_tag(event, root_tag, 4);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    const char* reply_tag[] = {"e", "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222", "wss://relay2.example.com", "reply"};
    err = nostr_event_add_tag(event, reply_tag, 4);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    char root_id[65];
    char relay_hint[256];
    err = nostr_event_get_root_id(event, root_id, sizeof(root_id), relay_hint, sizeof(relay_hint));
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL_STRING("aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", root_id);
    TEST_ASSERT_EQUAL_STRING("wss://relay.example.com", relay_hint);

    nostr_event_destroy(event);
}

static void test_get_reply_id_marked(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    const char* root_tag[] = {"e", "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", "wss://relay.example.com", "root"};
    err = nostr_event_add_tag(event, root_tag, 4);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    const char* reply_tag[] = {"e", "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222", "wss://relay2.example.com", "reply"};
    err = nostr_event_add_tag(event, reply_tag, 4);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    char reply_id[65];
    char relay_hint[256];
    err = nostr_event_get_reply_id(event, reply_id, sizeof(reply_id), relay_hint, sizeof(relay_hint));
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL_STRING("bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222", reply_id);
    TEST_ASSERT_EQUAL_STRING("wss://relay2.example.com", relay_hint);

    nostr_event_destroy(event);
}

static void test_get_root_id_positional(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    const char* first_tag[] = {"e", "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", "wss://relay.example.com"};
    err = nostr_event_add_tag(event, first_tag, 3);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    const char* second_tag[] = {"e", "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222", "wss://relay2.example.com"};
    err = nostr_event_add_tag(event, second_tag, 3);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    char root_id[65];
    char relay_hint[256];
    err = nostr_event_get_root_id(event, root_id, sizeof(root_id), relay_hint, sizeof(relay_hint));
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL_STRING("aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", root_id);

    nostr_event_destroy(event);
}

static void test_get_reply_id_positional(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    const char* first_tag[] = {"e", "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", "wss://relay.example.com"};
    err = nostr_event_add_tag(event, first_tag, 3);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    const char* second_tag[] = {"e", "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222", "wss://relay2.example.com"};
    err = nostr_event_add_tag(event, second_tag, 3);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    char reply_id[65];
    char relay_hint[256];
    err = nostr_event_get_reply_id(event, reply_id, sizeof(reply_id), relay_hint, sizeof(relay_hint));
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL_STRING("bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222", reply_id);

    nostr_event_destroy(event);
}

static void test_add_reply_tags_direct_reply(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_event_add_reply_tags(event, "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
                                     "wss://relay.example.com", NULL, NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL(1, event->tags_count);

    char root_id[65];
    err = nostr_event_get_root_id(event, root_id, sizeof(root_id), NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL_STRING("aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", root_id);

    nostr_event_destroy(event);
}

static void test_add_reply_tags_threaded(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_event_add_reply_tags(event,
                                     "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
                                     "wss://relay.example.com", "pubkey1",
                                     "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222",
                                     "wss://relay2.example.com", "pubkey2");
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL(2, event->tags_count);

    char root_id[65];
    char relay_hint[256];
    err = nostr_event_get_root_id(event, root_id, sizeof(root_id), relay_hint, sizeof(relay_hint));
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL_STRING("aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", root_id);

    char reply_id[65];
    err = nostr_event_get_reply_id(event, reply_id, sizeof(reply_id), NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL_STRING("bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222", reply_id);

    nostr_event_destroy(event);
}

static void test_add_mention_tag(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_event_add_mention_tag(event, "cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333", "wss://relay.example.com");
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL(1, event->tags_count);
    TEST_ASSERT_EQUAL_STRING("p", event->tags[0].values[0]);
    TEST_ASSERT_EQUAL_STRING("cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333", event->tags[0].values[1]);

    nostr_event_destroy(event);
}

static void test_is_reply(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    int is_reply = 0;
    err = nostr_event_is_reply(event, &is_reply);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL(0, is_reply);

    const char* e_tag[] = {"e", "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"};
    err = nostr_event_add_tag(event, e_tag, 2);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    err = nostr_event_is_reply(event, &is_reply);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL(1, is_reply);

    nostr_event_destroy(event);
}

static void test_no_e_tags(void)
{
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    char root_id[65];
    err = nostr_event_get_root_id(event, root_id, sizeof(root_id), NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_ERR_NOT_FOUND, err);

    nostr_event_destroy(event);
}

static void test_invalid_params(void)
{
    nostr_error_t err;

    err = nostr_event_get_root_id(NULL, NULL, 0, NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_event_get_reply_id(NULL, NULL, 0, NULL, 0);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_event_add_reply_tags(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    nostr_event* event = NULL;
    nostr_event_create(&event);
    err = nostr_event_add_reply_tags(event, NULL, NULL, NULL, NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);
    nostr_event_destroy(event);

    err = nostr_event_add_mention_tag(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);

    err = nostr_event_is_reply(NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);
}

void run_nip10_tests(void)
{
    printf("   Running NIP-10 tests...\n");

    test_get_root_id_marked();
    printf("     Success: test_get_root_id_marked\n");

    test_get_reply_id_marked();
    printf("     Success: test_get_reply_id_marked\n");

    test_get_root_id_positional();
    printf("     Success: test_get_root_id_positional\n");

    test_get_reply_id_positional();
    printf("     Success: test_get_reply_id_positional\n");

    test_add_reply_tags_direct_reply();
    printf("     Success: test_add_reply_tags_direct_reply\n");

    test_add_reply_tags_threaded();
    printf("     Success: test_add_reply_tags_threaded\n");

    test_add_mention_tag();
    printf("     Success: test_add_mention_tag\n");

    test_is_reply();
    printf("     Success: test_is_reply\n");

    test_no_e_tags();
    printf("     Success: test_no_e_tags\n");

    test_invalid_params();
    printf("     Success: test_invalid_params\n");
}

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    printf("Running NIP-10 tests...\n\n");
    run_nip10_tests();
    printf("\nAll NIP-10 tests completed!\n");
    return 0;
}
#endif

#else

void run_nip10_tests(void)
{
    printf("   NIP-10 tests skipped (NIP-10 not enabled)\n");
}

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    printf("NIP-10 not enabled in build\n");
    return 0;
}
#endif

#endif
