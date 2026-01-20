/**
 * @file test_relay_protocol_accessors.c
 * @brief Accessor function tests: hex conversion, filter/event/message accessors
 */

#ifdef HAVE_UNITY
#include "unity.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/nostr.h"
#include "../include/nostr_relay_protocol.h"

#ifndef HAVE_UNITY
static int g_test_failed = 0;
static int g_tests_failed_count = 0;

#define TEST_ASSERT_EQUAL(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("Assertion failed: %s != %s (expected %d, got %d)\n", #expected, #actual, (int)(expected), (int)(actual)); \
            g_test_failed = 1; \
            return; \
        } \
    } while(0)

#define TEST_ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            printf("Pointer is NULL: %s\n", #ptr); \
            g_test_failed = 1; \
            return; \
        } \
    } while(0)

#define TEST_ASSERT_NULL(ptr) \
    do { \
        if ((ptr) != NULL) { \
            printf("Pointer is not NULL: %s\n", #ptr); \
            g_test_failed = 1; \
            return; \
        } \
    } while(0)

#define TEST_ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            printf("Condition failed: %s\n", #condition); \
            g_test_failed = 1; \
            return; \
        } \
    } while(0)

#define TEST_ASSERT_FALSE(condition) \
    do { \
        if ((condition)) { \
            printf("Condition should be false: %s\n", #condition); \
            g_test_failed = 1; \
            return; \
        } \
    } while(0)

#define TEST_ASSERT_EQUAL_STRING(expected, actual) \
    do { \
        if (strcmp(expected, actual) != 0) { \
            printf("String comparison failed: '%s' != '%s'\n", expected, actual); \
            g_test_failed = 1; \
            return; \
        } \
    } while(0)

#define RUN_TEST(test_func, test_name) \
    do { \
        g_test_failed = 0; \
        test_func(); \
        if (g_test_failed) { \
            printf("  FAILED: %s\n", test_name); \
            g_tests_failed_count++; \
        } else { \
            printf("  Success: %s\n", test_name); \
        } \
    } while(0)
#endif

#ifdef HAVE_UNITY
void setUp(void) {}
void tearDown(void) {}
#endif

void test_nostr_hex_to_bytes(void)
{
    uint8_t out[32];
    nostr_relay_error_t err;

    err = nostr_hex_to_bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 64, out, 32);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(0x01, out[0]);
    TEST_ASSERT_EQUAL(0x23, out[1]);
    TEST_ASSERT_EQUAL(0xef, out[31]);

    err = nostr_hex_to_bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg", 64, out, 32);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_ID, err);

    err = nostr_hex_to_bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", 63, out, 32);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_ID, err);

    err = nostr_hex_to_bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 64, out, 31);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_BUFFER_TOO_SMALL, err);

    err = nostr_hex_to_bytes(NULL, 64, out, 32);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_ID, err);
    err = nostr_hex_to_bytes("abcd", 4, NULL, 2);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_ID, err);
}

void test_nostr_bytes_to_hex(void)
{
    uint8_t bytes[4] = {0x01, 0x23, 0xab, 0xcd};
    char out[9];

    nostr_bytes_to_hex(bytes, 4, out);
    TEST_ASSERT_EQUAL_STRING("0123abcd", out);

    nostr_bytes_to_hex(bytes, 0, out);
    TEST_ASSERT_EQUAL_STRING("", out);
}

void test_nostr_version(void)
{
    const char* version = nostr_version();
    TEST_ASSERT_NOT_NULL(version);
    TEST_ASSERT_TRUE(strlen(version) > 0);
}

void test_nostr_free(void)
{
    char* ptr = malloc(10);
    nostr_free(ptr);
    nostr_free(NULL);
}

void test_nostr_free_strings(void)
{
    char** strings = malloc(2 * sizeof(char*));
    if (!strings) return;
    strings[0] = strdup("hello");
    strings[1] = strdup("world");
    nostr_free_strings(strings, 2);

    nostr_free_strings(NULL, 0);
}

void test_filter_accessors(void)
{
#ifdef NOSTR_FEATURE_JSON_ENHANCED
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    const char* json = "{\"ids\":[\"abc123\"],\"authors\":[\"def456\"],\"kinds\":[1,2,3],\"since\":1000,\"until\":2000,\"limit\":100}";
    nostr_relay_error_t err = nostr_filter_parse(json, strlen(json), &filter);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);

    size_t count = 0;
    const char** ids = nostr_filter_get_ids(&filter, &count);
    TEST_ASSERT_NOT_NULL(ids);
    TEST_ASSERT_EQUAL(1, count);
    TEST_ASSERT_EQUAL_STRING("abc123", ids[0]);

    const char** authors = nostr_filter_get_authors(&filter, &count);
    TEST_ASSERT_NOT_NULL(authors);
    TEST_ASSERT_EQUAL(1, count);
    TEST_ASSERT_EQUAL_STRING("def456", authors[0]);

    const int32_t* kinds = nostr_filter_get_kinds(&filter, &count);
    TEST_ASSERT_NOT_NULL(kinds);
    TEST_ASSERT_EQUAL(3, count);
    TEST_ASSERT_EQUAL(1, kinds[0]);
    TEST_ASSERT_EQUAL(2, kinds[1]);
    TEST_ASSERT_EQUAL(3, kinds[2]);

    TEST_ASSERT_EQUAL(1000, nostr_filter_get_since(&filter));
    TEST_ASSERT_EQUAL(2000, nostr_filter_get_until(&filter));
    TEST_ASSERT_EQUAL(100, nostr_filter_get_limit(&filter));

    nostr_filter_free(&filter);
#endif
}

void test_filter_accessors_null(void)
{
    size_t count = 0;
    TEST_ASSERT_NULL(nostr_filter_get_ids(NULL, &count));
    TEST_ASSERT_EQUAL(0, count);
    TEST_ASSERT_NULL(nostr_filter_get_authors(NULL, &count));
    TEST_ASSERT_NULL(nostr_filter_get_kinds(NULL, &count));
    TEST_ASSERT_EQUAL(0, nostr_filter_get_since(NULL));
    TEST_ASSERT_EQUAL(0, nostr_filter_get_until(NULL));
    TEST_ASSERT_EQUAL(0, nostr_filter_get_limit(NULL));
}

void test_client_msg_accessors(void)
{
#ifdef NOSTR_FEATURE_JSON_ENHANCED
    nostr_client_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    const char* close_json = "[\"CLOSE\",\"sub123\"]";
    nostr_relay_error_t err = nostr_client_msg_parse(close_json, strlen(close_json), &msg);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);

    TEST_ASSERT_EQUAL(NOSTR_CLIENT_MSG_CLOSE, nostr_client_msg_get_type(&msg));
    TEST_ASSERT_EQUAL_STRING("sub123", nostr_client_msg_get_subscription_id(&msg));
    TEST_ASSERT_NULL(nostr_client_msg_get_event(&msg));

    nostr_client_msg_free(&msg);
#endif
}

void test_client_msg_accessors_null(void)
{
    TEST_ASSERT_EQUAL(NOSTR_CLIENT_MSG_UNKNOWN, nostr_client_msg_get_type(NULL));
    TEST_ASSERT_NULL(nostr_client_msg_get_event(NULL));
    TEST_ASSERT_NULL(nostr_client_msg_get_subscription_id(NULL));
    size_t count = 0;
    TEST_ASSERT_NULL(nostr_client_msg_get_filters(NULL, &count));
    TEST_ASSERT_EQUAL(0, count);
}

void test_event_accessors(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    const char* e_tag[] = {"e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36"};
    const char* p_tag[] = {"p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca"};
    const char* d_tag[] = {"d", "my-article", "extra-value"};

    nostr_event_add_tag(event, e_tag, 2);
    nostr_event_add_tag(event, p_tag, 2);
    nostr_event_add_tag(event, d_tag, 3);

    TEST_ASSERT_EQUAL(3, nostr_event_get_tag_count(event));

    const nostr_tag* tag = nostr_event_get_tag(event, 0);
    TEST_ASSERT_NOT_NULL(tag);

    TEST_ASSERT_EQUAL_STRING("e", nostr_tag_get_name(tag));
    TEST_ASSERT_EQUAL(2, nostr_tag_get_value_count(tag));
    TEST_ASSERT_EQUAL_STRING("e", nostr_tag_get_value(tag, 0));
    TEST_ASSERT_EQUAL_STRING("5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", nostr_tag_get_value(tag, 1));
    TEST_ASSERT_NULL(nostr_tag_get_value(tag, 2));

    const nostr_tag* d_tag_ptr = nostr_event_get_tag(event, 2);
    TEST_ASSERT_NOT_NULL(d_tag_ptr);
    TEST_ASSERT_EQUAL_STRING("d", nostr_tag_get_name(d_tag_ptr));
    TEST_ASSERT_EQUAL(3, nostr_tag_get_value_count(d_tag_ptr));
    TEST_ASSERT_EQUAL_STRING("d", nostr_tag_get_value(d_tag_ptr, 0));
    TEST_ASSERT_EQUAL_STRING("my-article", nostr_tag_get_value(d_tag_ptr, 1));
    TEST_ASSERT_EQUAL_STRING("extra-value", nostr_tag_get_value(d_tag_ptr, 2));

    const nostr_tag* found = nostr_event_find_tag(event, "p");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("p", nostr_tag_get_name(found));

    TEST_ASSERT_NULL(nostr_event_find_tag(event, "x"));

    TEST_ASSERT_NULL(nostr_event_get_tag(event, 100));

    nostr_event_destroy(event);
}

void test_event_accessors_null(void)
{
    TEST_ASSERT_EQUAL(0, nostr_event_get_tag_count(NULL));
    TEST_ASSERT_NULL(nostr_event_get_tag(NULL, 0));
    TEST_ASSERT_NULL(nostr_tag_get_name(NULL));
    TEST_ASSERT_EQUAL(0, nostr_tag_get_value_count(NULL));
    TEST_ASSERT_NULL(nostr_tag_get_value(NULL, 0));
    TEST_ASSERT_NULL(nostr_event_find_tag(NULL, "e"));
}

void test_event_is_deletion(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    event->kind = 1;
    TEST_ASSERT_FALSE(nostr_event_is_deletion(event));

    event->kind = 5;
    TEST_ASSERT_TRUE(nostr_event_is_deletion(event));

    TEST_ASSERT_FALSE(nostr_event_is_deletion(NULL));

    nostr_event_destroy(event);
}

void test_event_binary_tag_extractors(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    const char* e_tag1[] = {"e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36"};
    const char* e_tag2[] = {"e", "0000000000000000000000000000000000000000000000000000000000000001"};
    const char* p_tag[] = {"p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca"};
    const char* d_tag[] = {"d", "not-a-binary-tag"};

    nostr_event_add_tag(event, e_tag1, 2);
    nostr_event_add_tag(event, e_tag2, 2);
    nostr_event_add_tag(event, p_tag, 2);
    nostr_event_add_tag(event, d_tag, 2);

    size_t count = 0;
    uint8_t (*e_tags)[32] = nostr_event_get_e_tags_binary(event, &count);
    TEST_ASSERT_NOT_NULL(e_tags);
    TEST_ASSERT_EQUAL(2, count);
    TEST_ASSERT_EQUAL(0x5c, e_tags[0][0]);
    TEST_ASSERT_EQUAL(0x01, e_tags[1][31]);
    free(e_tags);

    uint8_t (*p_tags)[32] = nostr_event_get_p_tags_binary(event, &count);
    TEST_ASSERT_NOT_NULL(p_tags);
    TEST_ASSERT_EQUAL(1, count);
    TEST_ASSERT_EQUAL(0xf7, p_tags[0][0]);
    free(p_tags);

    TEST_ASSERT_NULL(nostr_event_get_e_tags_binary(NULL, &count));
    TEST_ASSERT_EQUAL(0, count);

    nostr_event_destroy(event);
}

void test_event_binary_tag_extractors_no_tags(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    size_t count = 0;
    uint8_t (*e_tags)[32] = nostr_event_get_e_tags_binary(event, &count);
    TEST_ASSERT_NULL(e_tags);
    TEST_ASSERT_EQUAL(0, count);

    nostr_event_destroy(event);
}

int run_relay_protocol_accessor_tests(void)
{
#ifndef HAVE_UNITY
    g_tests_failed_count = 0;
#endif

    printf("Running relay protocol accessor tests...\n");

#ifdef HAVE_UNITY
    RUN_TEST(test_nostr_hex_to_bytes);
    RUN_TEST(test_nostr_bytes_to_hex);
    RUN_TEST(test_nostr_version);
    RUN_TEST(test_nostr_free);
    RUN_TEST(test_nostr_free_strings);
    RUN_TEST(test_filter_accessors);
    RUN_TEST(test_filter_accessors_null);
    RUN_TEST(test_client_msg_accessors);
    RUN_TEST(test_client_msg_accessors_null);
    RUN_TEST(test_event_accessors);
    RUN_TEST(test_event_accessors_null);
    RUN_TEST(test_event_is_deletion);
    RUN_TEST(test_event_binary_tag_extractors);
    RUN_TEST(test_event_binary_tag_extractors_no_tags);
#else
    RUN_TEST(test_nostr_hex_to_bytes, "nostr_hex_to_bytes");
    RUN_TEST(test_nostr_bytes_to_hex, "nostr_bytes_to_hex");
    RUN_TEST(test_nostr_version, "nostr_version");
    RUN_TEST(test_nostr_free, "nostr_free");
    RUN_TEST(test_nostr_free_strings, "nostr_free_strings");
    RUN_TEST(test_filter_accessors, "filter_accessors");
    RUN_TEST(test_filter_accessors_null, "filter_accessors_null");
    RUN_TEST(test_client_msg_accessors, "client_msg_accessors");
    RUN_TEST(test_client_msg_accessors_null, "client_msg_accessors_null");
    RUN_TEST(test_event_accessors, "event_accessors");
    RUN_TEST(test_event_accessors_null, "event_accessors_null");
    RUN_TEST(test_event_is_deletion, "event_is_deletion");
    RUN_TEST(test_event_binary_tag_extractors, "event_binary_tag_extractors");
    RUN_TEST(test_event_binary_tag_extractors_no_tags, "event_binary_tag_extractors_no_tags");
#endif

#ifndef HAVE_UNITY
    if (g_tests_failed_count > 0) {
        printf("FAILED: %d test(s) failed!\n", g_tests_failed_count);
        return g_tests_failed_count;
    }
#endif
    printf("All relay protocol accessor tests passed!\n");
    return 0;
}

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    nostr_init();
    int result = run_relay_protocol_accessor_tests();
    nostr_cleanup();
    return result;
}
#endif
