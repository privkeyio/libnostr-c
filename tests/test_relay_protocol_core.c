/**
 * @file test_relay_protocol_core.c
 * @brief Core unit tests for relay protocol: validation, kinds, event helpers
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

void test_validate_hex64_valid(void)
{
    TEST_ASSERT_TRUE(nostr_validate_hex64("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    TEST_ASSERT_TRUE(nostr_validate_hex64("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    TEST_ASSERT_TRUE(nostr_validate_hex64("0000000000000000000000000000000000000000000000000000000000000000"));
}

void test_validate_hex64_invalid(void)
{
    TEST_ASSERT_FALSE(nostr_validate_hex64("0123456789abcdef"));
    TEST_ASSERT_FALSE(nostr_validate_hex64("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"));
    TEST_ASSERT_FALSE(nostr_validate_hex64("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeff"));
    TEST_ASSERT_FALSE(nostr_validate_hex64("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"));
    TEST_ASSERT_FALSE(nostr_validate_hex64("g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    TEST_ASSERT_FALSE(nostr_validate_hex64(NULL));
}

void test_validate_hex_prefix_valid(void)
{
    TEST_ASSERT_TRUE(nostr_validate_hex_prefix("0"));
    TEST_ASSERT_TRUE(nostr_validate_hex_prefix("0123456789abcdef"));
    TEST_ASSERT_TRUE(nostr_validate_hex_prefix("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
}

void test_validate_hex_prefix_invalid(void)
{
    TEST_ASSERT_FALSE(nostr_validate_hex_prefix(""));
    TEST_ASSERT_FALSE(nostr_validate_hex_prefix("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefa"));
    TEST_ASSERT_FALSE(nostr_validate_hex_prefix("ABC"));
    TEST_ASSERT_FALSE(nostr_validate_hex_prefix("xyz"));
    TEST_ASSERT_FALSE(nostr_validate_hex_prefix(NULL));
}

void test_validate_subscription_id_valid(void)
{
    TEST_ASSERT_TRUE(nostr_validate_subscription_id("sub1"));
    TEST_ASSERT_TRUE(nostr_validate_subscription_id("a"));
    TEST_ASSERT_TRUE(nostr_validate_subscription_id("my-subscription-123"));
    TEST_ASSERT_TRUE(nostr_validate_subscription_id("1234567890123456789012345678901234567890123456789012345678901234"));
}

void test_validate_subscription_id_invalid(void)
{
    TEST_ASSERT_FALSE(nostr_validate_subscription_id(""));
    TEST_ASSERT_FALSE(nostr_validate_subscription_id("12345678901234567890123456789012345678901234567890123456789012345"));
    TEST_ASSERT_FALSE(nostr_validate_subscription_id("sub\x01"));
    TEST_ASSERT_FALSE(nostr_validate_subscription_id("sub\n"));
    TEST_ASSERT_FALSE(nostr_validate_subscription_id(NULL));
}

void test_validate_timestamp(void)
{
    int64_t now = nostr_timestamp_now();
    TEST_ASSERT_TRUE(nostr_validate_timestamp(now - 1000, 900));
    TEST_ASSERT_TRUE(nostr_validate_timestamp(0, 900));
    TEST_ASSERT_TRUE(nostr_validate_timestamp(now, 900));
    TEST_ASSERT_TRUE(nostr_validate_timestamp(now + 800, 900));
    TEST_ASSERT_TRUE(nostr_validate_timestamp(now + 900, 900));
    TEST_ASSERT_FALSE(nostr_validate_timestamp(now + 1000, 900));
}

void test_kind_classification_regular(void)
{
    TEST_ASSERT_EQUAL(NOSTR_KIND_REGULAR, nostr_kind_get_type(1));
    TEST_ASSERT_EQUAL(NOSTR_KIND_REGULAR, nostr_kind_get_type(2));
    TEST_ASSERT_EQUAL(NOSTR_KIND_REGULAR, nostr_kind_get_type(7));
    TEST_ASSERT_EQUAL(NOSTR_KIND_REGULAR, nostr_kind_get_type(1000));
    TEST_ASSERT_EQUAL(NOSTR_KIND_REGULAR, nostr_kind_get_type(9999));
    TEST_ASSERT_TRUE(nostr_kind_is_regular(1));
    TEST_ASSERT_FALSE(nostr_kind_is_replaceable(1));
    TEST_ASSERT_FALSE(nostr_kind_is_ephemeral(1));
    TEST_ASSERT_FALSE(nostr_kind_is_addressable(1));
}

void test_kind_classification_replaceable(void)
{
    TEST_ASSERT_EQUAL(NOSTR_KIND_REPLACEABLE, nostr_kind_get_type(0));
    TEST_ASSERT_EQUAL(NOSTR_KIND_REPLACEABLE, nostr_kind_get_type(3));
    TEST_ASSERT_EQUAL(NOSTR_KIND_REPLACEABLE, nostr_kind_get_type(10000));
    TEST_ASSERT_EQUAL(NOSTR_KIND_REPLACEABLE, nostr_kind_get_type(19999));
    TEST_ASSERT_TRUE(nostr_kind_is_replaceable(0));
    TEST_ASSERT_TRUE(nostr_kind_is_replaceable(3));
    TEST_ASSERT_FALSE(nostr_kind_is_regular(0));
}

void test_kind_classification_ephemeral(void)
{
    TEST_ASSERT_EQUAL(NOSTR_KIND_EPHEMERAL, nostr_kind_get_type(20000));
    TEST_ASSERT_EQUAL(NOSTR_KIND_EPHEMERAL, nostr_kind_get_type(25000));
    TEST_ASSERT_EQUAL(NOSTR_KIND_EPHEMERAL, nostr_kind_get_type(29999));
    TEST_ASSERT_TRUE(nostr_kind_is_ephemeral(20000));
    TEST_ASSERT_FALSE(nostr_kind_is_regular(20000));
}

void test_kind_classification_addressable(void)
{
    TEST_ASSERT_EQUAL(NOSTR_KIND_ADDRESSABLE, nostr_kind_get_type(30000));
    TEST_ASSERT_EQUAL(NOSTR_KIND_ADDRESSABLE, nostr_kind_get_type(30023));
    TEST_ASSERT_EQUAL(NOSTR_KIND_ADDRESSABLE, nostr_kind_get_type(39999));
    TEST_ASSERT_TRUE(nostr_kind_is_addressable(30000));
    TEST_ASSERT_FALSE(nostr_kind_is_regular(30000));
}

void test_event_get_tag_value(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    const char* e_tag[] = {"e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36"};
    const char* p_tag[] = {"p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca"};
    const char* d_tag[] = {"d", "my-article"};

    nostr_event_add_tag(event, e_tag, 2);
    nostr_event_add_tag(event, p_tag, 2);
    nostr_event_add_tag(event, d_tag, 2);

    TEST_ASSERT_EQUAL_STRING("5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36",
                             nostr_event_get_tag_value(event, "e"));
    TEST_ASSERT_EQUAL_STRING("f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca",
                             nostr_event_get_tag_value(event, "p"));
    TEST_ASSERT_EQUAL_STRING("my-article", nostr_event_get_d_tag(event));
    TEST_ASSERT_NULL(nostr_event_get_tag_value(event, "x"));

    nostr_event_destroy(event);
}

void test_event_has_tag(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    const char* e_tag[] = {"e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36"};
    nostr_event_add_tag(event, e_tag, 2);

    TEST_ASSERT_TRUE(nostr_event_has_tag(event, "e"));
    TEST_ASSERT_FALSE(nostr_event_has_tag(event, "p"));
    TEST_ASSERT_FALSE(nostr_event_has_tag(event, "d"));

    nostr_event_destroy(event);
}

void test_event_get_tag_values(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    const char* e_tag1[] = {"e", "0000000000000000000000000000000000000000000000000000000000000001"};
    const char* e_tag2[] = {"e", "0000000000000000000000000000000000000000000000000000000000000002"};
    const char* e_tag3[] = {"e", "0000000000000000000000000000000000000000000000000000000000000003"};

    nostr_event_add_tag(event, e_tag1, 2);
    nostr_event_add_tag(event, e_tag2, 2);
    nostr_event_add_tag(event, e_tag3, 2);

    const char* values[10];
    size_t count = nostr_event_get_tag_values(event, "e", values, 10);

    TEST_ASSERT_EQUAL(3, count);
    TEST_ASSERT_EQUAL_STRING("0000000000000000000000000000000000000000000000000000000000000001", values[0]);
    TEST_ASSERT_EQUAL_STRING("0000000000000000000000000000000000000000000000000000000000000002", values[1]);
    TEST_ASSERT_EQUAL_STRING("0000000000000000000000000000000000000000000000000000000000000003", values[2]);

    count = nostr_event_get_tag_values(event, "e", values, 2);
    TEST_ASSERT_EQUAL(2, count);

    nostr_event_destroy(event);
}

void test_event_get_tag_at(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    const char* tag[] = {"a", "30023:pubkey:identifier", "wss://relay.example.com"};
    nostr_event_add_tag(event, tag, 3);

    size_t count = 0;
    const char** values = nostr_event_get_tag_at(event, 0, &count);

    TEST_ASSERT_NOT_NULL(values);
    TEST_ASSERT_EQUAL(3, count);
    TEST_ASSERT_EQUAL_STRING("a", values[0]);
    TEST_ASSERT_EQUAL_STRING("30023:pubkey:identifier", values[1]);
    TEST_ASSERT_EQUAL_STRING("wss://relay.example.com", values[2]);

    values = nostr_event_get_tag_at(event, 1, &count);
    TEST_ASSERT_NULL(values);
    TEST_ASSERT_EQUAL(0, count);

    nostr_event_destroy(event);
}

void test_event_expiration(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    TEST_ASSERT_EQUAL(0, nostr_event_get_expiration(event));
    TEST_ASSERT_FALSE(nostr_event_is_expired(event, nostr_timestamp_now()));

    const char* exp_tag[] = {"expiration", "1000000000"};
    nostr_event_add_tag(event, exp_tag, 2);

    TEST_ASSERT_EQUAL(1000000000, nostr_event_get_expiration(event));
    TEST_ASSERT_TRUE(nostr_event_is_expired(event, nostr_timestamp_now()));
    TEST_ASSERT_TRUE(nostr_event_is_expired_now(event));

    nostr_event_destroy(event);
}

void test_event_not_expired(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    const char* exp_tag[] = {"expiration", "9999999999"};
    nostr_event_add_tag(event, exp_tag, 2);

    TEST_ASSERT_EQUAL(9999999999LL, nostr_event_get_expiration(event));
    TEST_ASSERT_FALSE(nostr_event_is_expired(event, nostr_timestamp_now()));
    TEST_ASSERT_FALSE(nostr_event_is_expired_now(event));

    nostr_event_destroy(event);
}

void test_event_compare_replaceable(void)
{
    nostr_event* older = NULL;
    nostr_event* newer = NULL;

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&older));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&newer));

    older->created_at = 1000000000;
    newer->created_at = 1000000001;

    TEST_ASSERT_EQUAL(-1, nostr_event_compare_replaceable(older, newer));
    TEST_ASSERT_EQUAL(1, nostr_event_compare_replaceable(newer, older));

    newer->created_at = older->created_at;
    memset(older->id, 0x00, NOSTR_ID_SIZE);
    memset(newer->id, 0xFF, NOSTR_ID_SIZE);

    TEST_ASSERT_EQUAL(1, nostr_event_compare_replaceable(older, newer));
    TEST_ASSERT_EQUAL(-1, nostr_event_compare_replaceable(newer, older));

    nostr_event_destroy(older);
    nostr_event_destroy(newer);
}

void test_relay_msg_ok(void)
{
    nostr_relay_msg_t msg;
    nostr_relay_msg_ok(&msg, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true, "");

    TEST_ASSERT_EQUAL(NOSTR_RELAY_MSG_OK, msg.type);
    TEST_ASSERT_TRUE(msg.data.ok.success);
    TEST_ASSERT_EQUAL_STRING("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", msg.data.ok.event_id);
    TEST_ASSERT_EQUAL_STRING("", msg.data.ok.message);
}

void test_relay_msg_ok_with_message(void)
{
    nostr_relay_msg_t msg;
    nostr_relay_msg_ok(&msg, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                       false, "blocked: you are banned from posting here");

    TEST_ASSERT_EQUAL(NOSTR_RELAY_MSG_OK, msg.type);
    TEST_ASSERT_FALSE(msg.data.ok.success);
    TEST_ASSERT_EQUAL_STRING("blocked: you are banned from posting here", msg.data.ok.message);
}

void test_relay_msg_eose(void)
{
    nostr_relay_msg_t msg;
    nostr_relay_msg_eose(&msg, "sub1");

    TEST_ASSERT_EQUAL(NOSTR_RELAY_MSG_EOSE, msg.type);
    TEST_ASSERT_EQUAL_STRING("sub1", msg.data.eose.subscription_id);
}

void test_relay_msg_closed(void)
{
    nostr_relay_msg_t msg;
    nostr_relay_msg_closed(&msg, "sub1", "error: shutting down idle subscription");

    TEST_ASSERT_EQUAL(NOSTR_RELAY_MSG_CLOSED, msg.type);
    TEST_ASSERT_EQUAL_STRING("sub1", msg.data.closed.subscription_id);
    TEST_ASSERT_EQUAL_STRING("error: shutting down idle subscription", msg.data.closed.message);
}

void test_relay_msg_notice(void)
{
    nostr_relay_msg_t msg;
    nostr_relay_msg_notice(&msg, "Welcome to the relay!");

    TEST_ASSERT_EQUAL(NOSTR_RELAY_MSG_NOTICE, msg.type);
    TEST_ASSERT_EQUAL_STRING("Welcome to the relay!", msg.data.notice.message);
}

void test_relay_msg_auth(void)
{
    nostr_relay_msg_t msg;
    nostr_relay_msg_auth(&msg, "challenge-string-12345");

    TEST_ASSERT_EQUAL(NOSTR_RELAY_MSG_AUTH, msg.type);
    TEST_ASSERT_EQUAL_STRING("challenge-string-12345", msg.data.auth.challenge);
}

void test_relay_msg_count(void)
{
    nostr_relay_msg_t msg;
    nostr_relay_msg_count(&msg, "query123", 238, false);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_MSG_COUNT, msg.type);
    TEST_ASSERT_EQUAL_STRING("query123", msg.data.count.query_id);
    TEST_ASSERT_EQUAL(238, msg.data.count.count);
    TEST_ASSERT_FALSE(msg.data.count.approximate);
}

void test_relay_msg_count_approximate(void)
{
    nostr_relay_msg_t msg;
    nostr_relay_msg_count(&msg, "query456", 93412452, true);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_MSG_COUNT, msg.type);
    TEST_ASSERT_EQUAL_STRING("query456", msg.data.count.query_id);
    TEST_ASSERT_EQUAL(93412452, msg.data.count.count);
    TEST_ASSERT_TRUE(msg.data.count.approximate);
}

void test_relay_msg_count_negative(void)
{
    nostr_relay_msg_t msg;
    nostr_relay_msg_count(&msg, "query789", -5, false);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_MSG_COUNT, msg.type);
    TEST_ASSERT_EQUAL_STRING("query789", msg.data.count.query_id);
    TEST_ASSERT_EQUAL(0, msg.data.count.count);
    TEST_ASSERT_FALSE(msg.data.count.approximate);
}

void test_relay_error_string(void)
{
    TEST_ASSERT_EQUAL_STRING("OK", nostr_relay_error_string(NOSTR_RELAY_OK));
    TEST_ASSERT_EQUAL_STRING("invalid JSON", nostr_relay_error_string(NOSTR_RELAY_ERR_INVALID_JSON));
    TEST_ASSERT_EQUAL_STRING("event ID mismatch", nostr_relay_error_string(NOSTR_RELAY_ERR_ID_MISMATCH));
    TEST_ASSERT_EQUAL_STRING("signature verification failed", nostr_relay_error_string(NOSTR_RELAY_ERR_SIG_MISMATCH));
    TEST_ASSERT_EQUAL_STRING("event created_at too far in future", nostr_relay_error_string(NOSTR_RELAY_ERR_FUTURE_EVENT));
}

void test_validation_error_format(void)
{
    nostr_validation_result_t result;
    result.valid = false;
    result.error_code = NOSTR_RELAY_ERR_SIG_MISMATCH;
    strncpy(result.error_message, "signature verification failed", sizeof(result.error_message) - 1);
    strncpy(result.error_field, "sig", sizeof(result.error_field) - 1);

    char buf[256];
    size_t len = nostr_validation_error_format(&result, buf, sizeof(buf));

    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_TRUE(strstr(buf, "invalid:") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "signature verification failed") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "'sig'") != NULL);
}

void test_tag_iterator_basic(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    const char* e_tag[] = {"e", "0000000000000000000000000000000000000000000000000000000000000001"};
    const char* p_tag[] = {"p", "0000000000000000000000000000000000000000000000000000000000000002"};
    const char* t_tag[] = {"t", "nostr"};

    nostr_event_add_tag(event, e_tag, 2);
    nostr_event_add_tag(event, p_tag, 2);
    nostr_event_add_tag(event, t_tag, 2);

    nostr_tag_iterator_t iter;
    nostr_tag_iterator_init(&iter, event);

    size_t tag_len = 0;
    const char** values;
    int count = 0;

    while ((values = nostr_tag_iterator_next(&iter, &tag_len)) != NULL) {
        TEST_ASSERT_TRUE(tag_len == 2);
        count++;
    }

    TEST_ASSERT_EQUAL(3, count);

    nostr_event_destroy(event);
}

void test_tag_iterator_next_info(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    const char* e_tag[] = {"e", "event_id_here", "wss://relay.example.com"};
    nostr_event_add_tag(event, e_tag, 3);

    nostr_tag_iterator_t iter;
    nostr_tag_iterator_init(&iter, event);

    nostr_tag_info_t tag;
    TEST_ASSERT_TRUE(nostr_tag_iterator_next_info(&iter, &tag));

    TEST_ASSERT_EQUAL_STRING("e", tag.name);
    TEST_ASSERT_EQUAL(2, tag.values_count);
    TEST_ASSERT_EQUAL_STRING("event_id_here", tag.values[0]);
    TEST_ASSERT_EQUAL_STRING("wss://relay.example.com", tag.values[1]);

    TEST_ASSERT_FALSE(nostr_tag_iterator_next_info(&iter, &tag));

    nostr_event_destroy(event);
}

void test_tag_iterator_empty_event(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    nostr_tag_iterator_t iter;
    nostr_tag_iterator_init(&iter, event);

    size_t tag_len = 0;
    const char** values = nostr_tag_iterator_next(&iter, &tag_len);

    TEST_ASSERT_NULL(values);
    TEST_ASSERT_EQUAL(0, tag_len);

    nostr_event_destroy(event);
}

void test_tag_is_indexable(void)
{
    TEST_ASSERT_TRUE(nostr_tag_is_indexable("e"));
    TEST_ASSERT_TRUE(nostr_tag_is_indexable("p"));
    TEST_ASSERT_TRUE(nostr_tag_is_indexable("t"));
    TEST_ASSERT_TRUE(nostr_tag_is_indexable("a"));
    TEST_ASSERT_TRUE(nostr_tag_is_indexable("d"));
    TEST_ASSERT_TRUE(nostr_tag_is_indexable("A"));
    TEST_ASSERT_TRUE(nostr_tag_is_indexable("Z"));

    TEST_ASSERT_FALSE(nostr_tag_is_indexable(""));
    TEST_ASSERT_FALSE(nostr_tag_is_indexable("ab"));
    TEST_ASSERT_FALSE(nostr_tag_is_indexable("nonce"));
    TEST_ASSERT_FALSE(nostr_tag_is_indexable("1"));
    TEST_ASSERT_FALSE(nostr_tag_is_indexable("-"));
    TEST_ASSERT_FALSE(nostr_tag_is_indexable(NULL));
}

int run_relay_protocol_core_tests(void)
{
#ifndef HAVE_UNITY
    g_tests_failed_count = 0;
#endif

    printf("Running relay protocol core tests...\n");

#ifdef HAVE_UNITY
    RUN_TEST(test_validate_hex64_valid);
    RUN_TEST(test_validate_hex64_invalid);
    RUN_TEST(test_validate_hex_prefix_valid);
    RUN_TEST(test_validate_hex_prefix_invalid);
    RUN_TEST(test_validate_subscription_id_valid);
    RUN_TEST(test_validate_subscription_id_invalid);
    RUN_TEST(test_validate_timestamp);
    RUN_TEST(test_kind_classification_regular);
    RUN_TEST(test_kind_classification_replaceable);
    RUN_TEST(test_kind_classification_ephemeral);
    RUN_TEST(test_kind_classification_addressable);
    RUN_TEST(test_event_get_tag_value);
    RUN_TEST(test_event_has_tag);
    RUN_TEST(test_event_get_tag_values);
    RUN_TEST(test_event_get_tag_at);
    RUN_TEST(test_event_expiration);
    RUN_TEST(test_event_not_expired);
    RUN_TEST(test_event_compare_replaceable);
    RUN_TEST(test_relay_msg_ok);
    RUN_TEST(test_relay_msg_ok_with_message);
    RUN_TEST(test_relay_msg_eose);
    RUN_TEST(test_relay_msg_closed);
    RUN_TEST(test_relay_msg_notice);
    RUN_TEST(test_relay_msg_auth);
    RUN_TEST(test_relay_msg_count);
    RUN_TEST(test_relay_msg_count_approximate);
    RUN_TEST(test_relay_msg_count_negative);
    RUN_TEST(test_relay_error_string);
    RUN_TEST(test_validation_error_format);
    RUN_TEST(test_tag_iterator_basic);
    RUN_TEST(test_tag_iterator_next_info);
    RUN_TEST(test_tag_iterator_empty_event);
    RUN_TEST(test_tag_is_indexable);
#else
    RUN_TEST(test_validate_hex64_valid, "validate_hex64_valid");
    RUN_TEST(test_validate_hex64_invalid, "validate_hex64_invalid");
    RUN_TEST(test_validate_hex_prefix_valid, "validate_hex_prefix_valid");
    RUN_TEST(test_validate_hex_prefix_invalid, "validate_hex_prefix_invalid");
    RUN_TEST(test_validate_subscription_id_valid, "validate_subscription_id_valid");
    RUN_TEST(test_validate_subscription_id_invalid, "validate_subscription_id_invalid");
    RUN_TEST(test_validate_timestamp, "validate_timestamp");
    RUN_TEST(test_kind_classification_regular, "kind_classification_regular");
    RUN_TEST(test_kind_classification_replaceable, "kind_classification_replaceable");
    RUN_TEST(test_kind_classification_ephemeral, "kind_classification_ephemeral");
    RUN_TEST(test_kind_classification_addressable, "kind_classification_addressable");
    RUN_TEST(test_event_get_tag_value, "event_get_tag_value");
    RUN_TEST(test_event_has_tag, "event_has_tag");
    RUN_TEST(test_event_get_tag_values, "event_get_tag_values");
    RUN_TEST(test_event_get_tag_at, "event_get_tag_at");
    RUN_TEST(test_event_expiration, "event_expiration");
    RUN_TEST(test_event_not_expired, "event_not_expired");
    RUN_TEST(test_event_compare_replaceable, "event_compare_replaceable");
    RUN_TEST(test_relay_msg_ok, "relay_msg_ok");
    RUN_TEST(test_relay_msg_ok_with_message, "relay_msg_ok_with_message");
    RUN_TEST(test_relay_msg_eose, "relay_msg_eose");
    RUN_TEST(test_relay_msg_closed, "relay_msg_closed");
    RUN_TEST(test_relay_msg_notice, "relay_msg_notice");
    RUN_TEST(test_relay_msg_auth, "relay_msg_auth");
    RUN_TEST(test_relay_msg_count, "relay_msg_count");
    RUN_TEST(test_relay_msg_count_approximate, "relay_msg_count_approximate");
    RUN_TEST(test_relay_msg_count_negative, "relay_msg_count_negative");
    RUN_TEST(test_relay_error_string, "relay_error_string");
    RUN_TEST(test_validation_error_format, "validation_error_format");
    RUN_TEST(test_tag_iterator_basic, "tag_iterator_basic");
    RUN_TEST(test_tag_iterator_next_info, "tag_iterator_next_info");
    RUN_TEST(test_tag_iterator_empty_event, "tag_iterator_empty_event");
    RUN_TEST(test_tag_is_indexable, "tag_is_indexable");
#endif

#ifndef HAVE_UNITY
    if (g_tests_failed_count > 0) {
        printf("FAILED: %d test(s) failed!\n", g_tests_failed_count);
        return g_tests_failed_count;
    }
#endif
    printf("All relay protocol core tests passed!\n");
    return 0;
}

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    nostr_init();
    int result = run_relay_protocol_core_tests();
    nostr_cleanup();
    return result;
}
#endif
