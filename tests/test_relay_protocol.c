/**
 * @file test_relay_protocol.c
 * @brief Unit tests for NIP-01 relay protocol functions
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
#define TEST_ASSERT_EQUAL(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("Assertion failed: %s != %s (expected %d, got %d)\n", #expected, #actual, (int)(expected), (int)(actual)); \
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

#define TEST_ASSERT_NULL(ptr) \
    do { \
        if ((ptr) != NULL) { \
            printf("Pointer is not NULL: %s\n", #ptr); \
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

#define TEST_ASSERT_FALSE(condition) \
    do { \
        if ((condition)) { \
            printf("Condition should be false: %s\n", #condition); \
            return; \
        } \
    } while(0)

#define TEST_ASSERT_EQUAL_STRING(expected, actual) \
    do { \
        if (strcmp(expected, actual) != 0) { \
            printf("String comparison failed: '%s' != '%s'\n", expected, actual); \
            return; \
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

#ifdef NOSTR_FEATURE_JSON_ENHANCED

void test_filter_parse_empty(void)
{
    nostr_filter_t filter;
    nostr_relay_error_t err = nostr_filter_parse("{}", 2, &filter);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(0, filter.ids_count);
    TEST_ASSERT_EQUAL(0, filter.authors_count);
    TEST_ASSERT_EQUAL(0, filter.kinds_count);
    TEST_ASSERT_EQUAL(0, filter.e_tags_count);
    TEST_ASSERT_EQUAL(0, filter.p_tags_count);
    TEST_ASSERT_EQUAL(0, filter.since);
    TEST_ASSERT_EQUAL(0, filter.until);
    TEST_ASSERT_EQUAL(0, filter.limit);

    nostr_filter_free(&filter);
}

void test_filter_parse_kinds(void)
{
    const char* json = "{\"kinds\":[0,1,3]}";
    nostr_filter_t filter;
    nostr_relay_error_t err = nostr_filter_parse(json, strlen(json), &filter);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(3, filter.kinds_count);
    TEST_ASSERT_EQUAL(0, filter.kinds[0]);
    TEST_ASSERT_EQUAL(1, filter.kinds[1]);
    TEST_ASSERT_EQUAL(3, filter.kinds[2]);

    nostr_filter_free(&filter);
}

void test_filter_parse_authors(void)
{
    const char* json = "{\"authors\":[\"0123456789abcdef\"]}";
    nostr_filter_t filter;
    nostr_relay_error_t err = nostr_filter_parse(json, strlen(json), &filter);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(1, filter.authors_count);
    TEST_ASSERT_EQUAL_STRING("0123456789abcdef", filter.authors[0]);

    nostr_filter_free(&filter);
}

void test_filter_parse_since_until_limit(void)
{
    const char* json = "{\"since\":1000000000,\"until\":2000000000,\"limit\":100}";
    nostr_filter_t filter;
    nostr_relay_error_t err = nostr_filter_parse(json, strlen(json), &filter);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(1000000000, filter.since);
    TEST_ASSERT_EQUAL(2000000000, filter.until);
    TEST_ASSERT_EQUAL(100, filter.limit);

    nostr_filter_free(&filter);
}

void test_filter_parse_tags(void)
{
    const char* json = "{\"#e\":[\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"],\"#p\":[\"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\"]}";
    nostr_filter_t filter;
    nostr_relay_error_t err = nostr_filter_parse(json, strlen(json), &filter);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(1, filter.e_tags_count);
    TEST_ASSERT_EQUAL(1, filter.p_tags_count);
    TEST_ASSERT_EQUAL_STRING("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", filter.e_tags[0]);
    TEST_ASSERT_EQUAL_STRING("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", filter.p_tags[0]);

    nostr_filter_free(&filter);
}

void test_filter_parse_invalid_json(void)
{
    nostr_filter_t filter;
    nostr_relay_error_t err = nostr_filter_parse("not valid json", 14, &filter);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_JSON, err);
}

void test_filter_matches_empty_filter(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;
    event->created_at = 1000000000;

    TEST_ASSERT_TRUE(nostr_filter_matches(&filter, event));

    nostr_event_destroy(event);
}

void test_filter_matches_kind(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    int32_t kinds[] = {1, 7};
    filter.kinds = kinds;
    filter.kinds_count = 2;

    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    event->kind = 1;
    TEST_ASSERT_TRUE(nostr_filter_matches(&filter, event));

    event->kind = 7;
    TEST_ASSERT_TRUE(nostr_filter_matches(&filter, event));

    event->kind = 3;
    TEST_ASSERT_FALSE(nostr_filter_matches(&filter, event));

    nostr_event_destroy(event);
}

void test_filter_matches_since_until(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    filter.since = 1000;
    filter.until = 2000;

    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    event->created_at = 1500;
    TEST_ASSERT_TRUE(nostr_filter_matches(&filter, event));

    event->created_at = 1000;
    TEST_ASSERT_TRUE(nostr_filter_matches(&filter, event));

    event->created_at = 2000;
    TEST_ASSERT_TRUE(nostr_filter_matches(&filter, event));

    event->created_at = 999;
    TEST_ASSERT_FALSE(nostr_filter_matches(&filter, event));

    event->created_at = 2001;
    TEST_ASSERT_FALSE(nostr_filter_matches(&filter, event));

    nostr_event_destroy(event);
}

void test_filter_matches_e_tags(void)
{
    const char* json = "{\"#e\":[\"0000000000000000000000000000000000000000000000000000000000000001\"]}";
    nostr_filter_t filter;
    nostr_filter_parse(json, strlen(json), &filter);

    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    TEST_ASSERT_FALSE(nostr_filter_matches(&filter, event));

    const char* wrong_tag[] = {"e", "0000000000000000000000000000000000000000000000000000000000000002"};
    nostr_event_add_tag(event, wrong_tag, 2);
    TEST_ASSERT_FALSE(nostr_filter_matches(&filter, event));

    nostr_event_destroy(event);
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    const char* correct_tag[] = {"e", "0000000000000000000000000000000000000000000000000000000000000001"};
    nostr_event_add_tag(event, correct_tag, 2);
    TEST_ASSERT_TRUE(nostr_filter_matches(&filter, event));

    nostr_event_destroy(event);
    nostr_filter_free(&filter);
}

void test_filters_match_or_logic(void)
{
    nostr_filter_t filters[2];
    memset(filters, 0, sizeof(filters));

    int32_t kinds1[] = {1};
    int32_t kinds2[] = {7};

    filters[0].kinds = kinds1;
    filters[0].kinds_count = 1;
    filters[1].kinds = kinds2;
    filters[1].kinds_count = 1;

    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    event->kind = 1;
    TEST_ASSERT_TRUE(nostr_filters_match(filters, 2, event));

    event->kind = 7;
    TEST_ASSERT_TRUE(nostr_filters_match(filters, 2, event));

    event->kind = 3;
    TEST_ASSERT_FALSE(nostr_filters_match(filters, 2, event));

    nostr_event_destroy(event);
}

void test_client_msg_parse_close(void)
{
    const char* json = "[\"CLOSE\",\"sub1\"]";
    nostr_client_msg_t msg;

    nostr_relay_error_t err = nostr_client_msg_parse(json, strlen(json), &msg);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(NOSTR_CLIENT_MSG_CLOSE, msg.type);
    TEST_ASSERT_EQUAL_STRING("sub1", msg.data.close.subscription_id);

    nostr_client_msg_free(&msg);
}

void test_client_msg_parse_req(void)
{
    const char* json = "[\"REQ\",\"sub1\",{\"kinds\":[1],\"limit\":10}]";
    nostr_client_msg_t msg;

    nostr_relay_error_t err = nostr_client_msg_parse(json, strlen(json), &msg);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(NOSTR_CLIENT_MSG_REQ, msg.type);
    TEST_ASSERT_EQUAL_STRING("sub1", msg.data.req.subscription_id);
    TEST_ASSERT_EQUAL(1, msg.data.req.filters_count);
    TEST_ASSERT_EQUAL(1, msg.data.req.filters[0].kinds_count);
    TEST_ASSERT_EQUAL(1, msg.data.req.filters[0].kinds[0]);
    TEST_ASSERT_EQUAL(10, msg.data.req.filters[0].limit);

    nostr_client_msg_free(&msg);
}

void test_client_msg_parse_req_multiple_filters(void)
{
    const char* json = "[\"REQ\",\"sub1\",{\"kinds\":[0]},{\"kinds\":[1]}]";
    nostr_client_msg_t msg;

    nostr_relay_error_t err = nostr_client_msg_parse(json, strlen(json), &msg);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(NOSTR_CLIENT_MSG_REQ, msg.type);
    TEST_ASSERT_EQUAL(2, msg.data.req.filters_count);
    TEST_ASSERT_EQUAL(0, msg.data.req.filters[0].kinds[0]);
    TEST_ASSERT_EQUAL(1, msg.data.req.filters[1].kinds[0]);

    nostr_client_msg_free(&msg);
}

void test_client_msg_parse_invalid_json(void)
{
    nostr_client_msg_t msg;
    nostr_relay_error_t err = nostr_client_msg_parse("not json", 8, &msg);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_JSON, err);
}

void test_client_msg_parse_unknown_type(void)
{
    const char* json = "[\"UNKNOWN\"]";
    nostr_client_msg_t msg;
    nostr_relay_error_t err = nostr_client_msg_parse(json, strlen(json), &msg);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_UNKNOWN_MESSAGE_TYPE, err);
}

void test_relay_msg_serialize_ok(void)
{
    nostr_relay_msg_t msg;
    nostr_relay_msg_ok(&msg, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true, "");

    char buf[512];
    size_t len;
    nostr_relay_error_t err = nostr_relay_msg_serialize(&msg, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(strstr(buf, "\"OK\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "true") != NULL);
}

void test_relay_msg_serialize_eose(void)
{
    nostr_relay_msg_t msg;
    nostr_relay_msg_eose(&msg, "sub1");

    char buf[256];
    size_t len;
    nostr_relay_error_t err = nostr_relay_msg_serialize(&msg, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(strstr(buf, "\"EOSE\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"sub1\"") != NULL);
}

void test_relay_msg_serialize_notice(void)
{
    nostr_relay_msg_t msg;
    nostr_relay_msg_notice(&msg, "Hello!");

    char buf[256];
    size_t len;
    nostr_relay_error_t err = nostr_relay_msg_serialize(&msg, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(strstr(buf, "\"NOTICE\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"Hello!\"") != NULL);
}

void test_relay_msg_serialize_buffer_too_small(void)
{
    nostr_relay_msg_t msg;
    nostr_relay_msg_notice(&msg, "This is a long message that won't fit");

    char buf[10];
    size_t len;
    nostr_relay_error_t err = nostr_relay_msg_serialize(&msg, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_BUFFER_TOO_SMALL, err);
}

void test_event_parse_valid(void)
{
    const char* json = "{"
        "\"id\":\"0000000000000000000000000000000000000000000000000000000000000001\","
        "\"pubkey\":\"0000000000000000000000000000000000000000000000000000000000000002\","
        "\"created_at\":1700000000,"
        "\"kind\":1,"
        "\"tags\":[[\"e\",\"0000000000000000000000000000000000000000000000000000000000000003\"]],"
        "\"content\":\"Hello, Nostr!\","
        "\"sig\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\""
    "}";

    nostr_event* event = NULL;
    nostr_relay_error_t err = nostr_event_parse(json, strlen(json), &event);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL(1, event->kind);
    TEST_ASSERT_EQUAL(1700000000, event->created_at);
    TEST_ASSERT_EQUAL_STRING("Hello, Nostr!", event->content);
    TEST_ASSERT_EQUAL(1, event->tags_count);
    TEST_ASSERT_EQUAL_STRING("e", event->tags[0].values[0]);

    nostr_event_destroy(event);
}

void test_event_parse_invalid_json(void)
{
    nostr_event* event = NULL;
    nostr_relay_error_t err = nostr_event_parse("not valid json", 14, &event);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_JSON, err);
    TEST_ASSERT_NULL(event);
}

void test_event_parse_null_params(void)
{
    nostr_event* event = NULL;

    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_JSON, nostr_event_parse(NULL, 0, &event));
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_JSON, nostr_event_parse("{}", 2, NULL));
}

void test_event_serialize_valid(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    event->kind = 1;
    event->created_at = 1700000000;
    nostr_event_set_content(event, "Hello, World!");

    memset(event->pubkey.data, 0xAB, NOSTR_PUBKEY_SIZE);

    char buf[4096];
    size_t len = 0;
    nostr_relay_error_t err = nostr_event_serialize(event, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_TRUE(strstr(buf, "\"kind\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"content\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "Hello, World!") != NULL);

    nostr_event_destroy(event);
}

void test_event_serialize_buffer_too_small(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    event->kind = 1;
    nostr_event_set_content(event, "Hello, World!");

    char buf[10];
    size_t len = 0;
    nostr_relay_error_t err = nostr_event_serialize(event, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_BUFFER_TOO_SMALL, err);
    TEST_ASSERT_TRUE(len > 10);

    nostr_event_destroy(event);
}

void test_event_serialize_canonical_format(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    event->kind = 1;
    event->created_at = 1700000000;
    nostr_event_set_content(event, "Test");
    memset(event->pubkey.data, 0x00, NOSTR_PUBKEY_SIZE);

    char buf[4096];
    size_t len = 0;
    nostr_relay_error_t err = nostr_event_serialize_canonical(event, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_TRUE(buf[0] == '[');
    TEST_ASSERT_TRUE(strstr(buf, "[0,\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "0000000000000000000000000000000000000000000000000000000000000000") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "1700000000") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, ",1,") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"Test\"") != NULL);

    nostr_event_destroy(event);
}

void test_event_serialize_canonical_with_tags(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    event->kind = 1;
    event->created_at = 1700000000;
    nostr_event_set_content(event, "Tagged");

    const char* e_tag[] = {"e", "0000000000000000000000000000000000000000000000000000000000000001"};
    nostr_event_add_tag(event, e_tag, 2);

    char buf[4096];
    size_t len = 0;
    nostr_relay_error_t err = nostr_event_serialize_canonical(event, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(strstr(buf, "[\"e\",\"0000000000000000000000000000000000000000000000000000000000000001\"]") != NULL);

    nostr_event_destroy(event);
}

void test_event_serialize_canonical_escaping(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    event->kind = 1;
    event->created_at = 1700000000;
    nostr_event_set_content(event, "Line1\nLine2\tTabbed\"Quoted\"\\Backslash");

    char buf[4096];
    size_t len = 0;
    nostr_relay_error_t err = nostr_event_serialize_canonical(event, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(strstr(buf, "\\n") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\\t") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\\\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\\\\") != NULL);

    nostr_event_destroy(event);
}

void test_event_serialize_canonical_buffer_too_small(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    event->kind = 1;
    nostr_event_set_content(event, "Hello");

    char buf[10];
    size_t len = 0;
    nostr_relay_error_t err = nostr_event_serialize_canonical(event, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_BUFFER_TOO_SMALL, err);

    nostr_event_destroy(event);
}

#endif

void run_relay_protocol_tests(void)
{
    printf("Running relay protocol tests...\n");

    test_validate_hex64_valid();
    printf("  Success: validate_hex64_valid\n");
    test_validate_hex64_invalid();
    printf("  Success: validate_hex64_invalid\n");
    test_validate_hex_prefix_valid();
    printf("  Success: validate_hex_prefix_valid\n");
    test_validate_hex_prefix_invalid();
    printf("  Success: validate_hex_prefix_invalid\n");
    test_validate_subscription_id_valid();
    printf("  Success: validate_subscription_id_valid\n");
    test_validate_subscription_id_invalid();
    printf("  Success: validate_subscription_id_invalid\n");
    test_validate_timestamp();
    printf("  Success: validate_timestamp\n");

    test_kind_classification_regular();
    printf("  Success: kind_classification_regular\n");
    test_kind_classification_replaceable();
    printf("  Success: kind_classification_replaceable\n");
    test_kind_classification_ephemeral();
    printf("  Success: kind_classification_ephemeral\n");
    test_kind_classification_addressable();
    printf("  Success: kind_classification_addressable\n");

    test_event_get_tag_value();
    printf("  Success: event_get_tag_value\n");
    test_event_has_tag();
    printf("  Success: event_has_tag\n");
    test_event_get_tag_values();
    printf("  Success: event_get_tag_values\n");
    test_event_get_tag_at();
    printf("  Success: event_get_tag_at\n");

    test_event_expiration();
    printf("  Success: event_expiration\n");
    test_event_not_expired();
    printf("  Success: event_not_expired\n");

    test_event_compare_replaceable();
    printf("  Success: event_compare_replaceable\n");

    test_relay_msg_ok();
    printf("  Success: relay_msg_ok\n");
    test_relay_msg_ok_with_message();
    printf("  Success: relay_msg_ok_with_message\n");
    test_relay_msg_eose();
    printf("  Success: relay_msg_eose\n");
    test_relay_msg_closed();
    printf("  Success: relay_msg_closed\n");
    test_relay_msg_notice();
    printf("  Success: relay_msg_notice\n");
    test_relay_msg_auth();
    printf("  Success: relay_msg_auth\n");

    test_relay_error_string();
    printf("  Success: relay_error_string\n");
    test_validation_error_format();
    printf("  Success: validation_error_format\n");

#ifdef NOSTR_FEATURE_JSON_ENHANCED
    printf("  Running JSON-dependent tests...\n");

    test_filter_parse_empty();
    printf("  Success: filter_parse_empty\n");
    test_filter_parse_kinds();
    printf("  Success: filter_parse_kinds\n");
    test_filter_parse_authors();
    printf("  Success: filter_parse_authors\n");
    test_filter_parse_since_until_limit();
    printf("  Success: filter_parse_since_until_limit\n");
    test_filter_parse_tags();
    printf("  Success: filter_parse_tags\n");
    test_filter_parse_invalid_json();
    printf("  Success: filter_parse_invalid_json\n");

    test_filter_matches_empty_filter();
    printf("  Success: filter_matches_empty_filter\n");
    test_filter_matches_kind();
    printf("  Success: filter_matches_kind\n");
    test_filter_matches_since_until();
    printf("  Success: filter_matches_since_until\n");
    test_filter_matches_e_tags();
    printf("  Success: filter_matches_e_tags\n");
    test_filters_match_or_logic();
    printf("  Success: filters_match_or_logic\n");

    test_client_msg_parse_close();
    printf("  Success: client_msg_parse_close\n");
    test_client_msg_parse_req();
    printf("  Success: client_msg_parse_req\n");
    test_client_msg_parse_req_multiple_filters();
    printf("  Success: client_msg_parse_req_multiple_filters\n");
    test_client_msg_parse_invalid_json();
    printf("  Success: client_msg_parse_invalid_json\n");
    test_client_msg_parse_unknown_type();
    printf("  Success: client_msg_parse_unknown_type\n");

    test_relay_msg_serialize_ok();
    printf("  Success: relay_msg_serialize_ok\n");
    test_relay_msg_serialize_eose();
    printf("  Success: relay_msg_serialize_eose\n");
    test_relay_msg_serialize_notice();
    printf("  Success: relay_msg_serialize_notice\n");
    test_relay_msg_serialize_buffer_too_small();
    printf("  Success: relay_msg_serialize_buffer_too_small\n");

    /* Event parsing and serialization tests */
    test_event_parse_valid();
    printf("  Success: event_parse_valid\n");
    test_event_parse_invalid_json();
    printf("  Success: event_parse_invalid_json\n");
    test_event_parse_null_params();
    printf("  Success: event_parse_null_params\n");

    test_event_serialize_valid();
    printf("  Success: event_serialize_valid\n");
    test_event_serialize_buffer_too_small();
    printf("  Success: event_serialize_buffer_too_small\n");

    test_event_serialize_canonical_format();
    printf("  Success: event_serialize_canonical_format\n");
    test_event_serialize_canonical_with_tags();
    printf("  Success: event_serialize_canonical_with_tags\n");
    test_event_serialize_canonical_escaping();
    printf("  Success: event_serialize_canonical_escaping\n");
    test_event_serialize_canonical_buffer_too_small();
    printf("  Success: event_serialize_canonical_buffer_too_small\n");
#else
    printf("  (JSON-dependent tests skipped - NOSTR_FEATURE_JSON_ENHANCED not enabled)\n");
#endif

    printf("All relay protocol tests passed!\n");
}

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    nostr_init();
    run_relay_protocol_tests();
    nostr_cleanup();
    return 0;
}
#endif
