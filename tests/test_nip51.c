#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nostr.h"

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

static int test_list_create_free(void)
{
    nostr_list* list = NULL;

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_create(&list, NOSTR_LIST_KIND_MUTE));
    TEST_ASSERT_NOT_NULL(list);
    TEST_ASSERT_EQUAL(0, nostr_list_count(list));

    nostr_list_free(list);
    return 0;
}

static int test_list_create_invalid(void)
{
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_list_create(NULL, NOSTR_LIST_KIND_MUTE));
    return 0;
}

static int test_list_add_pubkey(void)
{
    nostr_list* list = NULL;
    nostr_list_create(&list, NOSTR_LIST_KIND_MUTE);

    const char* pubkey = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_add_pubkey(list, pubkey, NULL, NULL, false));
    TEST_ASSERT_EQUAL(1, nostr_list_count(list));

    const nostr_list_item* item = nostr_list_get(list, 0);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL_STRING("p", item->tag_type);
    TEST_ASSERT_EQUAL_STRING(pubkey, item->value);
    TEST_ASSERT_TRUE(!item->is_private);

    nostr_list_free(list);
    return 0;
}

static int test_list_add_pubkey_with_hints(void)
{
    nostr_list* list = NULL;
    nostr_list_create(&list, NOSTR_LIST_KIND_FOLLOW_SET);

    const char* pubkey = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    const char* relay = "wss://relay.example.com";
    const char* petname = "alice";

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_add_pubkey(list, pubkey, relay, petname, false));
    TEST_ASSERT_EQUAL(1, nostr_list_count(list));

    const nostr_list_item* item = nostr_list_get(list, 0);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL_STRING("p", item->tag_type);
    TEST_ASSERT_EQUAL_STRING(pubkey, item->value);
    TEST_ASSERT_EQUAL_STRING(relay, item->relay_hint);
    TEST_ASSERT_EQUAL_STRING(petname, item->petname);

    nostr_list_free(list);
    return 0;
}

static int test_list_add_pubkey_invalid(void)
{
    nostr_list* list = NULL;
    nostr_list_create(&list, NOSTR_LIST_KIND_MUTE);

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_list_add_pubkey(list, NULL, NULL, NULL, false));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_list_add_pubkey(list, "short", NULL, NULL, false));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_list_add_pubkey(NULL, "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", NULL, NULL, false));

    nostr_list_free(list);
    return 0;
}

static int test_list_add_event(void)
{
    nostr_list* list = NULL;
    nostr_list_create(&list, NOSTR_LIST_KIND_PIN);

    const char* event_id = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_add_event(list, event_id, "wss://relay.test", false));
    TEST_ASSERT_EQUAL(1, nostr_list_count(list));

    const nostr_list_item* item = nostr_list_get(list, 0);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL_STRING("e", item->tag_type);
    TEST_ASSERT_EQUAL_STRING(event_id, item->value);
    TEST_ASSERT_EQUAL_STRING("wss://relay.test", item->relay_hint);

    nostr_list_free(list);
    return 0;
}

static int test_list_add_hashtag(void)
{
    nostr_list* list = NULL;
    nostr_list_create(&list, NOSTR_LIST_KIND_MUTE);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_add_hashtag(list, "nostr", false));
    TEST_ASSERT_EQUAL(1, nostr_list_count(list));

    const nostr_list_item* item = nostr_list_get(list, 0);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL_STRING("t", item->tag_type);
    TEST_ASSERT_EQUAL_STRING("nostr", item->value);

    nostr_list_free(list);
    return 0;
}

static int test_list_add_word(void)
{
    nostr_list* list = NULL;
    nostr_list_create(&list, NOSTR_LIST_KIND_MUTE);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_add_word(list, "spam", false));
    TEST_ASSERT_EQUAL(1, nostr_list_count(list));

    const nostr_list_item* item = nostr_list_get(list, 0);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL_STRING("word", item->tag_type);
    TEST_ASSERT_EQUAL_STRING("spam", item->value);

    nostr_list_free(list);
    return 0;
}

static int test_list_add_relay(void)
{
    nostr_list* list = NULL;
    nostr_list_create(&list, NOSTR_LIST_KIND_RELAY_SET);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_add_relay(list, "wss://relay.example.com", false));
    TEST_ASSERT_EQUAL(1, nostr_list_count(list));

    const nostr_list_item* item = nostr_list_get(list, 0);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL_STRING("relay", item->tag_type);
    TEST_ASSERT_EQUAL_STRING("wss://relay.example.com", item->value);

    nostr_list_free(list);
    return 0;
}

static int test_list_add_reference(void)
{
    nostr_list* list = NULL;
    nostr_list_create(&list, NOSTR_LIST_KIND_BOOKMARK);

    const char* ref = "30023:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890:my-article";

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_add_reference(list, ref, "wss://relay.example.com", false));
    TEST_ASSERT_EQUAL(1, nostr_list_count(list));

    const nostr_list_item* item = nostr_list_get(list, 0);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL_STRING("a", item->tag_type);
    TEST_ASSERT_EQUAL_STRING(ref, item->value);

    nostr_list_free(list);
    return 0;
}

static int test_list_remove(void)
{
    nostr_list* list = NULL;
    nostr_list_create(&list, NOSTR_LIST_KIND_MUTE);

    const char* pk1 = "1111111111111111111111111111111111111111111111111111111111111111";
    const char* pk2 = "2222222222222222222222222222222222222222222222222222222222222222";
    const char* pk3 = "3333333333333333333333333333333333333333333333333333333333333333";

    nostr_list_add_pubkey(list, pk1, NULL, NULL, false);
    nostr_list_add_pubkey(list, pk2, NULL, NULL, false);
    nostr_list_add_pubkey(list, pk3, NULL, NULL, false);

    TEST_ASSERT_EQUAL(3, nostr_list_count(list));

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_remove(list, 1));
    TEST_ASSERT_EQUAL(2, nostr_list_count(list));

    const nostr_list_item* item = nostr_list_get(list, 0);
    TEST_ASSERT_EQUAL_STRING(pk1, item->value);

    item = nostr_list_get(list, 1);
    TEST_ASSERT_EQUAL_STRING(pk3, item->value);

    nostr_list_free(list);
    return 0;
}

static int test_list_to_event_standard(void)
{
    nostr_list* list = NULL;
    nostr_event* event = NULL;

    nostr_list_create(&list, NOSTR_LIST_KIND_MUTE);

    const char* pk1 = "1111111111111111111111111111111111111111111111111111111111111111";
    const char* pk2 = "2222222222222222222222222222222222222222222222222222222222222222";

    nostr_list_add_pubkey(list, pk1, NULL, NULL, false);
    nostr_list_add_pubkey(list, pk2, "wss://relay.test", NULL, false);
    nostr_list_add_hashtag(list, "spam", false);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_to_event(list, NULL, &event));
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL(10000, event->kind);
    TEST_ASSERT_EQUAL(3, event->tags_count);

    TEST_ASSERT_EQUAL_STRING("p", event->tags[0].values[0]);
    TEST_ASSERT_EQUAL_STRING(pk1, event->tags[0].values[1]);

    TEST_ASSERT_EQUAL_STRING("p", event->tags[1].values[0]);
    TEST_ASSERT_EQUAL_STRING(pk2, event->tags[1].values[1]);
    TEST_ASSERT_EQUAL_STRING("wss://relay.test", event->tags[1].values[2]);

    TEST_ASSERT_EQUAL_STRING("t", event->tags[2].values[0]);
    TEST_ASSERT_EQUAL_STRING("spam", event->tags[2].values[1]);

    nostr_event_destroy(event);
    nostr_list_free(list);
    return 0;
}

static int test_list_to_event_parameterized(void)
{
    nostr_list* list = NULL;
    nostr_event* event = NULL;

    nostr_list_create(&list, NOSTR_LIST_KIND_FOLLOW_SET);
    nostr_list_set_d_tag(list, "friends");
    nostr_list_set_title(list, "Close Friends");
    nostr_list_set_description(list, "My close friends list");

    const char* pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    nostr_list_add_pubkey(list, pk, NULL, "alice", false);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_to_event(list, NULL, &event));
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL(30000, event->kind);

    bool found_d = false, found_title = false, found_desc = false, found_p = false;

    for (size_t i = 0; i < event->tags_count; i++) {
        const char* tag_type = event->tags[i].values[0];
        if (strcmp(tag_type, "d") == 0) {
            TEST_ASSERT_EQUAL_STRING("friends", event->tags[i].values[1]);
            found_d = true;
        } else if (strcmp(tag_type, "title") == 0) {
            TEST_ASSERT_EQUAL_STRING("Close Friends", event->tags[i].values[1]);
            found_title = true;
        } else if (strcmp(tag_type, "description") == 0) {
            TEST_ASSERT_EQUAL_STRING("My close friends list", event->tags[i].values[1]);
            found_desc = true;
        } else if (strcmp(tag_type, "p") == 0) {
            TEST_ASSERT_EQUAL_STRING(pk, event->tags[i].values[1]);
            found_p = true;
        }
    }

    TEST_ASSERT_TRUE(found_d);
    TEST_ASSERT_TRUE(found_title);
    TEST_ASSERT_TRUE(found_desc);
    TEST_ASSERT_TRUE(found_p);

    nostr_event_destroy(event);
    nostr_list_free(list);
    return 0;
}

static int test_list_from_event(void)
{
    nostr_list* original = NULL;
    nostr_event* event = NULL;
    nostr_list* parsed = NULL;

    nostr_list_create(&original, NOSTR_LIST_KIND_BOOKMARK);

    const char* event_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const char* ref = "30023:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:article";

    nostr_list_add_event(original, event_id, "wss://relay.test", false);
    nostr_list_add_reference(original, ref, NULL, false);

    nostr_list_to_event(original, NULL, &event);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_from_event(event, NULL, &parsed));
    TEST_ASSERT_NOT_NULL(parsed);
    TEST_ASSERT_EQUAL(2, nostr_list_count(parsed));

    const nostr_list_item* item = nostr_list_get(parsed, 0);
    TEST_ASSERT_EQUAL_STRING("e", item->tag_type);
    TEST_ASSERT_EQUAL_STRING(event_id, item->value);

    item = nostr_list_get(parsed, 1);
    TEST_ASSERT_EQUAL_STRING("a", item->tag_type);
    TEST_ASSERT_EQUAL_STRING(ref, item->value);

    nostr_list_free(parsed);
    nostr_event_destroy(event);
    nostr_list_free(original);
    return 0;
}

static int test_list_from_event_parameterized(void)
{
    nostr_list* original = NULL;
    nostr_event* event = NULL;
    nostr_list* parsed = NULL;

    nostr_list_create(&original, NOSTR_LIST_KIND_INTEREST_SET);
    nostr_list_set_d_tag(original, "tech");
    nostr_list_set_title(original, "Tech Topics");
    nostr_list_set_description(original, "Technology interests");

    nostr_list_add_hashtag(original, "programming", false);
    nostr_list_add_hashtag(original, "bitcoin", false);

    nostr_list_to_event(original, NULL, &event);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_from_event(event, NULL, &parsed));
    TEST_ASSERT_NOT_NULL(parsed);

    TEST_ASSERT_NOT_NULL(parsed->d_tag);
    TEST_ASSERT_EQUAL_STRING("tech", parsed->d_tag);
    TEST_ASSERT_NOT_NULL(parsed->title);
    TEST_ASSERT_EQUAL_STRING("Tech Topics", parsed->title);
    TEST_ASSERT_NOT_NULL(parsed->description);
    TEST_ASSERT_EQUAL_STRING("Technology interests", parsed->description);

    TEST_ASSERT_EQUAL(2, nostr_list_count(parsed));

    nostr_list_free(parsed);
    nostr_event_destroy(event);
    nostr_list_free(original);
    return 0;
}

static int test_list_set_metadata(void)
{
    nostr_list* list = NULL;
    nostr_list_create(&list, NOSTR_LIST_KIND_CURATION_SET);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_set_d_tag(list, "my-curation"));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_set_title(list, "My Curation"));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_set_description(list, "A description"));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_set_image(list, "https://example.com/image.png"));

    TEST_ASSERT_EQUAL_STRING("my-curation", list->d_tag);
    TEST_ASSERT_EQUAL_STRING("My Curation", list->title);
    TEST_ASSERT_EQUAL_STRING("A description", list->description);
    TEST_ASSERT_EQUAL_STRING("https://example.com/image.png", list->image);

    nostr_list_free(list);
    return 0;
}

static int test_list_capacity_growth(void)
{
    nostr_list* list = NULL;
    nostr_list_create(&list, NOSTR_LIST_KIND_MUTE);

    for (int i = 0; i < 50; i++) {
        char pk[65];
        snprintf(pk, sizeof(pk), "%064x", i);
        TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_add_pubkey(list, pk, NULL, NULL, false));
    }

    TEST_ASSERT_EQUAL(50, nostr_list_count(list));

    nostr_list_free(list);
    return 0;
}

static int test_list_get_out_of_bounds(void)
{
    nostr_list* list = NULL;
    nostr_list_create(&list, NOSTR_LIST_KIND_PIN);

    const char* event_id = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    nostr_list_add_event(list, event_id, NULL, false);

    TEST_ASSERT_NULL(nostr_list_get(list, 1));
    TEST_ASSERT_NULL(nostr_list_get(list, 100));
    TEST_ASSERT_NULL(nostr_list_get(NULL, 0));

    nostr_list_free(list);
    return 0;
}

static int test_list_kinds(void)
{
    nostr_list* list = NULL;

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_create(&list, NOSTR_LIST_KIND_MUTE));
    nostr_list_free(list);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_create(&list, NOSTR_LIST_KIND_PIN));
    nostr_list_free(list);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_create(&list, NOSTR_LIST_KIND_BOOKMARK));
    nostr_list_free(list);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_create(&list, NOSTR_LIST_KIND_FOLLOW_SET));
    nostr_list_free(list);

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_list_create(&list, NOSTR_LIST_KIND_RELAY_SET));
    nostr_list_free(list);

    return 0;
}

int main(void)
{
    int failures = 0;

#ifdef NOSTR_FEATURE_NIP51
    printf("Running NIP-51 tests...\n\n");

    RUN_TEST(test_list_create_free);
    RUN_TEST(test_list_create_invalid);
    RUN_TEST(test_list_add_pubkey);
    RUN_TEST(test_list_add_pubkey_with_hints);
    RUN_TEST(test_list_add_pubkey_invalid);
    RUN_TEST(test_list_add_event);
    RUN_TEST(test_list_add_hashtag);
    RUN_TEST(test_list_add_word);
    RUN_TEST(test_list_add_relay);
    RUN_TEST(test_list_add_reference);
    RUN_TEST(test_list_remove);
    RUN_TEST(test_list_to_event_standard);
    RUN_TEST(test_list_to_event_parameterized);
    RUN_TEST(test_list_from_event);
    RUN_TEST(test_list_from_event_parameterized);
    RUN_TEST(test_list_set_metadata);
    RUN_TEST(test_list_capacity_growth);
    RUN_TEST(test_list_get_out_of_bounds);
    RUN_TEST(test_list_kinds);

    printf("\n");
    if (failures == 0) {
        printf("All NIP-51 tests passed!\n");
    } else {
        printf("%d test(s) failed.\n", failures);
    }
#else
    printf("NIP-51 not enabled, skipping tests.\n");
#endif

    return failures;
}
