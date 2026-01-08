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

/* ============================================================================
 * NIP-09 Event Deletion Tests
 * ============================================================================ */

void test_deletion_parse_basic(void)
{
    nostr_event* deletion_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&deletion_event));

    deletion_event->kind = 5;
    nostr_event_set_content(deletion_event, "These posts were published by accident");
    memset(deletion_event->pubkey.data, 0xAB, NOSTR_PUBKEY_SIZE);

    const char* e_tag1[] = {"e", "0000000000000000000000000000000000000000000000000000000000000001"};
    const char* e_tag2[] = {"e", "0000000000000000000000000000000000000000000000000000000000000002"};
    nostr_event_add_tag(deletion_event, e_tag1, 2);
    nostr_event_add_tag(deletion_event, e_tag2, 2);

    nostr_deletion_request_t request;
    nostr_relay_error_t err = nostr_deletion_parse(deletion_event, &request);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(2, request.event_ids_count);
    TEST_ASSERT_EQUAL_STRING("0000000000000000000000000000000000000000000000000000000000000001", request.event_ids[0]);
    TEST_ASSERT_EQUAL_STRING("0000000000000000000000000000000000000000000000000000000000000002", request.event_ids[1]);
    TEST_ASSERT_NOT_NULL(request.reason);
    TEST_ASSERT_EQUAL_STRING("These posts were published by accident", request.reason);

    nostr_deletion_free(&request);
    nostr_event_destroy(deletion_event);
}

void test_deletion_parse_with_addresses(void)
{
    nostr_event* deletion_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&deletion_event));

    deletion_event->kind = 5;
    memset(deletion_event->pubkey.data, 0xAB, NOSTR_PUBKEY_SIZE);

    const char* a_tag1[] = {"a", "30023:abababababababababababababababababababababababababababababababab:my-article"};
    const char* a_tag2[] = {"a", "30023:abababababababababababababababababababababababababababababababab:another-article"};
    nostr_event_add_tag(deletion_event, a_tag1, 2);
    nostr_event_add_tag(deletion_event, a_tag2, 2);

    nostr_deletion_request_t request;
    nostr_relay_error_t err = nostr_deletion_parse(deletion_event, &request);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(0, request.event_ids_count);
    TEST_ASSERT_EQUAL(2, request.addresses_count);
    TEST_ASSERT_EQUAL_STRING("30023:abababababababababababababababababababababababababababababababab:my-article", request.addresses[0]);
    TEST_ASSERT_EQUAL_STRING("30023:abababababababababababababababababababababababababababababababab:another-article", request.addresses[1]);

    nostr_deletion_free(&request);
    nostr_event_destroy(deletion_event);
}

void test_deletion_parse_invalid_kind(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    event->kind = 1;

    nostr_deletion_request_t request;
    nostr_relay_error_t err = nostr_deletion_parse(event, &request);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_KIND, err);

    nostr_event_destroy(event);
}

void test_deletion_parse_null_params(void)
{
    nostr_deletion_request_t request;
    nostr_event event;

    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_MISSING_FIELD, nostr_deletion_parse(NULL, &request));
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_MISSING_FIELD, nostr_deletion_parse(&event, NULL));
}

void test_deletion_authorized_same_pubkey(void)
{
    nostr_event* deletion_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&deletion_event));
    deletion_event->kind = 5;
    memset(deletion_event->pubkey.data, 0xAB, NOSTR_PUBKEY_SIZE);

    nostr_event* target_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&target_event));
    target_event->kind = 1;
    memset(target_event->pubkey.data, 0xAB, NOSTR_PUBKEY_SIZE);
    memset(target_event->id, 0x00, NOSTR_ID_SIZE);
    target_event->id[31] = 0x01;

    const char* e_tag[] = {"e", "0000000000000000000000000000000000000000000000000000000000000001"};
    nostr_event_add_tag(deletion_event, e_tag, 2);

    nostr_deletion_request_t request;
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, nostr_deletion_parse(deletion_event, &request));

    TEST_ASSERT_TRUE(nostr_deletion_authorized(&request, target_event));

    nostr_deletion_free(&request);
    nostr_event_destroy(deletion_event);
    nostr_event_destroy(target_event);
}

void test_deletion_unauthorized_different_pubkey(void)
{
    nostr_event* deletion_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&deletion_event));
    deletion_event->kind = 5;
    memset(deletion_event->pubkey.data, 0xAB, NOSTR_PUBKEY_SIZE);

    nostr_event* target_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&target_event));
    target_event->kind = 1;
    memset(target_event->pubkey.data, 0xCD, NOSTR_PUBKEY_SIZE);
    memset(target_event->id, 0x00, NOSTR_ID_SIZE);
    target_event->id[31] = 0x01;

    const char* e_tag[] = {"e", "0000000000000000000000000000000000000000000000000000000000000001"};
    nostr_event_add_tag(deletion_event, e_tag, 2);

    nostr_deletion_request_t request;
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, nostr_deletion_parse(deletion_event, &request));

    TEST_ASSERT_FALSE(nostr_deletion_authorized(&request, target_event));

    nostr_deletion_free(&request);
    nostr_event_destroy(deletion_event);
    nostr_event_destroy(target_event);
}

void test_deletion_unauthorized_event_not_listed(void)
{
    nostr_event* deletion_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&deletion_event));
    deletion_event->kind = 5;
    memset(deletion_event->pubkey.data, 0xAB, NOSTR_PUBKEY_SIZE);

    nostr_event* target_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&target_event));
    target_event->kind = 1;
    memset(target_event->pubkey.data, 0xAB, NOSTR_PUBKEY_SIZE);
    memset(target_event->id, 0xFF, NOSTR_ID_SIZE);

    const char* e_tag[] = {"e", "0000000000000000000000000000000000000000000000000000000000000001"};
    nostr_event_add_tag(deletion_event, e_tag, 2);

    nostr_deletion_request_t request;
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, nostr_deletion_parse(deletion_event, &request));

    TEST_ASSERT_FALSE(nostr_deletion_authorized(&request, target_event));

    nostr_deletion_free(&request);
    nostr_event_destroy(deletion_event);
    nostr_event_destroy(target_event);
}

void test_deletion_authorized_address(void)
{
    nostr_event* deletion_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&deletion_event));
    deletion_event->kind = 5;
    memset(deletion_event->pubkey.data, 0xAB, NOSTR_PUBKEY_SIZE);

    nostr_event* target_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&target_event));
    target_event->kind = 30023;
    memset(target_event->pubkey.data, 0xAB, NOSTR_PUBKEY_SIZE);

    const char* d_tag[] = {"d", "my-article"};
    nostr_event_add_tag(target_event, d_tag, 2);

    const char* a_tag[] = {"a", "30023:abababababababababababababababababababababababababababababababab:my-article"};
    nostr_event_add_tag(deletion_event, a_tag, 2);

    nostr_deletion_request_t request;
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, nostr_deletion_parse(deletion_event, &request));

    TEST_ASSERT_TRUE(nostr_deletion_authorized_address(&request, target_event));

    nostr_deletion_free(&request);
    nostr_event_destroy(deletion_event);
    nostr_event_destroy(target_event);
}

void test_deletion_unauthorized_address_different_pubkey(void)
{
    nostr_event* deletion_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&deletion_event));
    deletion_event->kind = 5;
    memset(deletion_event->pubkey.data, 0xAB, NOSTR_PUBKEY_SIZE);

    nostr_event* target_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&target_event));
    target_event->kind = 30023;
    memset(target_event->pubkey.data, 0xCD, NOSTR_PUBKEY_SIZE);

    const char* d_tag[] = {"d", "my-article"};
    nostr_event_add_tag(target_event, d_tag, 2);

    const char* a_tag[] = {"a", "30023:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd:my-article"};
    nostr_event_add_tag(deletion_event, a_tag, 2);

    nostr_deletion_request_t request;
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, nostr_deletion_parse(deletion_event, &request));

    TEST_ASSERT_FALSE(nostr_deletion_authorized_address(&request, target_event));

    nostr_deletion_free(&request);
    nostr_event_destroy(deletion_event);
    nostr_event_destroy(target_event);
}

void test_deletion_unauthorized_address_non_addressable(void)
{
    nostr_event* deletion_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&deletion_event));
    deletion_event->kind = 5;
    memset(deletion_event->pubkey.data, 0xAB, NOSTR_PUBKEY_SIZE);

    nostr_event* target_event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&target_event));
    target_event->kind = 1;
    memset(target_event->pubkey.data, 0xAB, NOSTR_PUBKEY_SIZE);

    const char* a_tag[] = {"a", "1:abababababababababababababababababababababababababababababababab:test"};
    nostr_event_add_tag(deletion_event, a_tag, 2);

    nostr_deletion_request_t request;
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, nostr_deletion_parse(deletion_event, &request));

    TEST_ASSERT_FALSE(nostr_deletion_authorized_address(&request, target_event));

    nostr_deletion_free(&request);
    nostr_event_destroy(deletion_event);
    nostr_event_destroy(target_event);
}

void test_deletion_free_null(void)
{
    nostr_deletion_free(NULL);
}

/* ============================================================================
 * NIP-11 Relay Information Document Tests
 * ============================================================================ */

void test_relay_limitation_init(void)
{
    nostr_relay_limitation_t limitation;
    nostr_relay_limitation_init(&limitation);

    TEST_ASSERT_EQUAL(NOSTR_DEFAULT_MAX_MESSAGE_LENGTH, limitation.max_message_length);
    TEST_ASSERT_EQUAL(NOSTR_DEFAULT_MAX_SUBSCRIPTIONS, limitation.max_subscriptions);
    TEST_ASSERT_EQUAL(NOSTR_DEFAULT_MAX_FILTERS, limitation.max_filters);
    TEST_ASSERT_EQUAL(NOSTR_DEFAULT_MAX_LIMIT, limitation.max_limit);
    TEST_ASSERT_EQUAL(NOSTR_DEFAULT_MAX_SUBID_LENGTH, limitation.max_subid_length);
    TEST_ASSERT_EQUAL(NOSTR_DEFAULT_MAX_EVENT_TAGS, limitation.max_event_tags);
    TEST_ASSERT_EQUAL(NOSTR_DEFAULT_MAX_CONTENT_LENGTH, limitation.max_content_length);
    TEST_ASSERT_EQUAL(NOSTR_DEFAULT_DEFAULT_LIMIT, limitation.default_limit);
    TEST_ASSERT_EQUAL(0, limitation.min_pow_difficulty);
    TEST_ASSERT_FALSE(limitation.auth_required);
    TEST_ASSERT_FALSE(limitation.payment_required);
    TEST_ASSERT_FALSE(limitation.restricted_writes);
    TEST_ASSERT_EQUAL(0, limitation.created_at_lower_limit);
    TEST_ASSERT_EQUAL(0, limitation.created_at_upper_limit);
}

void test_relay_info_init(void)
{
    nostr_relay_info_t info;
    nostr_relay_info_init(&info);

    TEST_ASSERT_NULL(info.name);
    TEST_ASSERT_NULL(info.description);
    TEST_ASSERT_NULL(info.pubkey);
    TEST_ASSERT_NULL(info.contact);
    TEST_ASSERT_NULL(info.software);
    TEST_ASSERT_NULL(info.version);
    TEST_ASSERT_NULL(info.icon);
    TEST_ASSERT_EQUAL(0, info.supported_nips_count);
    TEST_ASSERT_EQUAL(NOSTR_DEFAULT_MAX_MESSAGE_LENGTH, info.limitation.max_message_length);
}

void test_relay_info_set_nips(void)
{
    nostr_relay_info_t info;
    nostr_relay_info_init(&info);

    int32_t nips[] = {1, 9, 11, 40};
    nostr_relay_error_t err = nostr_relay_info_set_nips(&info, nips, 4);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(4, info.supported_nips_count);
    TEST_ASSERT_EQUAL(1, info.supported_nips[0]);
    TEST_ASSERT_EQUAL(9, info.supported_nips[1]);
    TEST_ASSERT_EQUAL(11, info.supported_nips[2]);
    TEST_ASSERT_EQUAL(40, info.supported_nips[3]);
}

void test_relay_info_add_nip(void)
{
    nostr_relay_info_t info;
    nostr_relay_info_init(&info);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, nostr_relay_info_add_nip(&info, 1));
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, nostr_relay_info_add_nip(&info, 9));
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, nostr_relay_info_add_nip(&info, 11));

    TEST_ASSERT_EQUAL(3, info.supported_nips_count);
    TEST_ASSERT_EQUAL(1, info.supported_nips[0]);
    TEST_ASSERT_EQUAL(9, info.supported_nips[1]);
    TEST_ASSERT_EQUAL(11, info.supported_nips[2]);

    nostr_relay_info_free(&info);
}

void test_relay_info_free(void)
{
    nostr_relay_info_t info;
    nostr_relay_info_init(&info);

    nostr_relay_info_add_nip(&info, 1);
    nostr_relay_info_add_nip(&info, 11);

    nostr_relay_info_free(&info);

    TEST_ASSERT_EQUAL(0, info.supported_nips_count);
    TEST_ASSERT_NULL(info.supported_nips);
}

void test_relay_info_free_null(void)
{
    nostr_relay_info_free(NULL);
}

#ifdef NOSTR_FEATURE_JSON_ENHANCED

void test_relay_limitation_serialize(void)
{
    nostr_relay_limitation_t limitation;
    nostr_relay_limitation_init(&limitation);

    limitation.auth_required = true;
    limitation.payment_required = true;
    limitation.restricted_writes = true;
    limitation.min_pow_difficulty = 30;

    char buf[4096];
    size_t len = 0;
    nostr_relay_error_t err = nostr_relay_limitation_serialize(&limitation, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_TRUE(strstr(buf, "\"max_message_length\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"auth_required\":true") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"payment_required\":true") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"restricted_writes\":true") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"min_pow_difficulty\":30") != NULL);
}

void test_relay_limitation_serialize_buffer_too_small(void)
{
    nostr_relay_limitation_t limitation;
    nostr_relay_limitation_init(&limitation);

    char buf[10];
    size_t len = 0;
    nostr_relay_error_t err = nostr_relay_limitation_serialize(&limitation, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_BUFFER_TOO_SMALL, err);
    TEST_ASSERT_TRUE(len > 10);
}

void test_relay_info_serialize_minimal(void)
{
    nostr_relay_info_t info;
    nostr_relay_info_init(&info);

    info.name = "My Relay";

    char buf[8192];
    size_t len = 0;
    nostr_relay_error_t err = nostr_relay_info_serialize(&info, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_TRUE(strstr(buf, "\"name\":\"My Relay\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"supported_nips\":[]") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"limitation\":{") != NULL);
}

void test_relay_info_serialize_full(void)
{
    nostr_relay_info_t info;
    nostr_relay_info_init(&info);

    info.name = "JellyFish";
    info.description = "Stay Immortal!";
    info.banner = "https://example.com/banner.jpg";
    info.icon = "https://example.com/icon.jpg";
    info.pubkey = "bf2bee5281149c7c350f5d12ae32f514c7864ff10805182f4178538c2c421007";
    info.contact = "hi@dezh.tech";
    info.software = "https://github.com/dezh-tech/immortal";
    info.version = "immortal - 0.0.9";
    info.privacy_policy = "https://example.com/privacy.txt";
    info.terms_of_service = "https://example.com/tos.txt";

    int32_t nips[] = {1, 9, 11, 13, 17, 40, 42};
    nostr_relay_info_set_nips(&info, nips, 7);

    info.limitation.auth_required = false;
    info.limitation.payment_required = true;
    info.limitation.restricted_writes = true;
    info.limitation.max_message_length = 70000;
    info.limitation.max_subscriptions = 350;
    info.limitation.max_limit = 5000;
    info.limitation.max_event_tags = 2000;
    info.limitation.max_content_length = 70000;
    info.limitation.default_limit = 500;

    char buf[16384];
    size_t len = 0;
    nostr_relay_error_t err = nostr_relay_info_serialize(&info, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(len > 0);

    TEST_ASSERT_TRUE(strstr(buf, "\"name\":\"JellyFish\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"description\":\"Stay Immortal!\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"banner\":\"https://example.com/banner.jpg\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"icon\":\"https://example.com/icon.jpg\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"pubkey\":\"bf2bee5281149c7c350f5d12ae32f514c7864ff10805182f4178538c2c421007\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"contact\":\"hi@dezh.tech\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"software\":\"https://github.com/dezh-tech/immortal\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"version\":\"immortal - 0.0.9\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"privacy_policy\":\"https://example.com/privacy.txt\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"terms_of_service\":\"https://example.com/tos.txt\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"supported_nips\":[1,9,11,13,17,40,42]") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"payment_required\":true") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"restricted_writes\":true") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"max_message_length\":70000") != NULL);
}

void test_relay_info_serialize_with_countries_and_tags(void)
{
    nostr_relay_info_t info;
    nostr_relay_info_init(&info);

    info.name = "Test Relay";

    const char* countries[] = {"US", "CA"};
    info.relay_countries = countries;
    info.relay_countries_count = 2;

    const char* languages[] = {"en", "en-419"};
    info.language_tags = languages;
    info.language_tags_count = 2;

    const char* tags[] = {"sfw-only", "bitcoin-only"};
    info.tags = tags;
    info.tags_count = 2;

    info.posting_policy = "https://example.com/policy.html";

    char buf[8192];
    size_t len = 0;
    nostr_relay_error_t err = nostr_relay_info_serialize(&info, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(strstr(buf, "\"relay_countries\":[\"US\",\"CA\"]") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"language_tags\":[\"en\",\"en-419\"]") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"tags\":[\"sfw-only\",\"bitcoin-only\"]") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"posting_policy\":\"https://example.com/policy.html\"") != NULL);
}

void test_relay_info_serialize_buffer_too_small(void)
{
    nostr_relay_info_t info;
    nostr_relay_info_init(&info);
    info.name = "My Relay";

    char buf[10];
    size_t len = 0;
    nostr_relay_error_t err = nostr_relay_info_serialize(&info, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_BUFFER_TOO_SMALL, err);
}

void test_relay_info_serialize_null_fields_omitted(void)
{
    nostr_relay_info_t info;
    nostr_relay_info_init(&info);

    info.name = "Minimal Relay";
    info.limitation.max_message_length = 0;
    info.limitation.max_subscriptions = 0;
    info.limitation.min_pow_difficulty = 0;

    char buf[8192];
    size_t len = 0;
    nostr_relay_error_t err = nostr_relay_info_serialize(&info, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(strstr(buf, "\"description\"") == NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"banner\"") == NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"pubkey\"") == NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"min_pow_difficulty\"") == NULL);
}

void test_relay_info_serialize_with_fees(void)
{
    nostr_relay_info_t info;
    nostr_relay_info_init(&info);

    info.name = "Paid Relay";
    info.payments_url = "https://my-relay/payments";

    nostr_relay_fee_t sub_fees[2];
    memset(sub_fees, 0, sizeof(sub_fees));
    sub_fees[0].amount = 3000;
    sub_fees[0].unit = "sats";
    sub_fees[0].period = 2628003;
    sub_fees[1].amount = 8000;
    sub_fees[1].unit = "sats";
    sub_fees[1].period = 7884009;

    info.fees.subscription = sub_fees;
    info.fees.subscription_count = 2;

    int32_t pub_kinds[] = {4};
    nostr_relay_fee_t pub_fees[1];
    memset(pub_fees, 0, sizeof(pub_fees));
    pub_fees[0].kinds = pub_kinds;
    pub_fees[0].kinds_count = 1;
    pub_fees[0].amount = 100;
    pub_fees[0].unit = "msats";

    info.fees.publication = pub_fees;
    info.fees.publication_count = 1;

    char buf[8192];
    size_t len = 0;
    nostr_relay_error_t err = nostr_relay_info_serialize(&info, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(strstr(buf, "\"payments_url\":\"https://my-relay/payments\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"fees\":{") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"subscription\":[") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"amount\":3000") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"unit\":\"sats\"") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"period\":2628003") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"publication\":[") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"kinds\":[4]") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"amount\":100") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"unit\":\"msats\"") != NULL);
}

void test_relay_info_serialize_with_retention(void)
{
    nostr_relay_info_t info;
    nostr_relay_info_init(&info);

    info.name = "Test Relay";

    int32_t kinds1[] = {0, 1, 7};
    nostr_relay_retention_t retention[2];
    memset(retention, 0, sizeof(retention));
    retention[0].kinds = kinds1;
    retention[0].kinds_count = 3;
    retention[0].time = 3600;
    retention[1].time = 7200;
    retention[1].count = 10000;

    info.retention = retention;
    info.retention_count = 2;

    char buf[8192];
    size_t len = 0;
    nostr_relay_error_t err = nostr_relay_info_serialize(&info, buf, sizeof(buf), &len);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_TRUE(strstr(buf, "\"retention\":[") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"kinds\":[0,1,7]") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"time\":3600") != NULL);
    TEST_ASSERT_TRUE(strstr(buf, "\"count\":10000") != NULL);
}

#endif

/* ============================================================================
 * Tag Iteration Tests
 * ============================================================================ */

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

/* ============================================================================
 * Filter Tag Accessor Tests
 * ============================================================================ */

void test_filter_get_e_tags(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    char* e_tags[] = {"id1", "id2", "id3"};
    filter.e_tags = e_tags;
    filter.e_tags_count = 3;

    size_t count = 0;
    const char** tags = nostr_filter_get_e_tags(&filter, &count);

    TEST_ASSERT_NOT_NULL(tags);
    TEST_ASSERT_EQUAL(3, count);
    TEST_ASSERT_EQUAL_STRING("id1", tags[0]);
    TEST_ASSERT_EQUAL_STRING("id2", tags[1]);
    TEST_ASSERT_EQUAL_STRING("id3", tags[2]);
}

void test_filter_get_p_tags(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    char* p_tags[] = {"pk1", "pk2"};
    filter.p_tags = p_tags;
    filter.p_tags_count = 2;

    size_t count = 0;
    const char** tags = nostr_filter_get_p_tags(&filter, &count);

    TEST_ASSERT_NOT_NULL(tags);
    TEST_ASSERT_EQUAL(2, count);
}

void test_filter_get_tag_values_generic(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    nostr_generic_tag_filter_t generic[1];
    char* t_values[] = {"bitcoin", "nostr"};
    generic[0].tag_name = 't';
    generic[0].values = t_values;
    generic[0].values_count = 2;

    filter.generic_tags = generic;
    filter.generic_tags_count = 1;

    size_t count = 0;
    const char** values = nostr_filter_get_tag_values(&filter, 't', &count);

    TEST_ASSERT_NOT_NULL(values);
    TEST_ASSERT_EQUAL(2, count);
    TEST_ASSERT_EQUAL_STRING("bitcoin", values[0]);
    TEST_ASSERT_EQUAL_STRING("nostr", values[1]);
}

void test_filter_get_tag_values_not_found(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    size_t count = 99;
    const char** values = nostr_filter_get_tag_values(&filter, 'x', &count);

    TEST_ASSERT_NULL(values);
    TEST_ASSERT_EQUAL(0, count);
}

void test_filter_has_tag_filters(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    TEST_ASSERT_FALSE(nostr_filter_has_tag_filters(&filter));

    char* e_tags[] = {"id1"};
    filter.e_tags = e_tags;
    filter.e_tags_count = 1;

    TEST_ASSERT_TRUE(nostr_filter_has_tag_filters(&filter));
}

void test_filter_has_tag_filters_null(void)
{
    TEST_ASSERT_FALSE(nostr_filter_has_tag_filters(NULL));
}

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

    /* NIP-09 Event Deletion tests (not JSON-dependent) */
    printf("  Running NIP-09 deletion tests...\n");

    test_deletion_parse_basic();
    printf("  Success: deletion_parse_basic\n");
    test_deletion_parse_with_addresses();
    printf("  Success: deletion_parse_with_addresses\n");
    test_deletion_parse_invalid_kind();
    printf("  Success: deletion_parse_invalid_kind\n");
    test_deletion_parse_null_params();
    printf("  Success: deletion_parse_null_params\n");
    test_deletion_authorized_same_pubkey();
    printf("  Success: deletion_authorized_same_pubkey\n");
    test_deletion_unauthorized_different_pubkey();
    printf("  Success: deletion_unauthorized_different_pubkey\n");
    test_deletion_unauthorized_event_not_listed();
    printf("  Success: deletion_unauthorized_event_not_listed\n");
    test_deletion_authorized_address();
    printf("  Success: deletion_authorized_address\n");
    test_deletion_unauthorized_address_different_pubkey();
    printf("  Success: deletion_unauthorized_address_different_pubkey\n");
    test_deletion_unauthorized_address_non_addressable();
    printf("  Success: deletion_unauthorized_address_non_addressable\n");
    test_deletion_free_null();
    printf("  Success: deletion_free_null\n");

    /* NIP-11 Relay Information Document tests */
    printf("  Running NIP-11 relay information tests...\n");

    test_relay_limitation_init();
    printf("  Success: relay_limitation_init\n");
    test_relay_info_init();
    printf("  Success: relay_info_init\n");
    test_relay_info_set_nips();
    printf("  Success: relay_info_set_nips\n");
    test_relay_info_add_nip();
    printf("  Success: relay_info_add_nip\n");
    test_relay_info_free();
    printf("  Success: relay_info_free\n");
    test_relay_info_free_null();
    printf("  Success: relay_info_free_null\n");

#ifdef NOSTR_FEATURE_JSON_ENHANCED
    printf("  Running NIP-11 serialization tests...\n");

    test_relay_limitation_serialize();
    printf("  Success: relay_limitation_serialize\n");
    test_relay_limitation_serialize_buffer_too_small();
    printf("  Success: relay_limitation_serialize_buffer_too_small\n");
    test_relay_info_serialize_minimal();
    printf("  Success: relay_info_serialize_minimal\n");
    test_relay_info_serialize_full();
    printf("  Success: relay_info_serialize_full\n");
    test_relay_info_serialize_with_countries_and_tags();
    printf("  Success: relay_info_serialize_with_countries_and_tags\n");
    test_relay_info_serialize_buffer_too_small();
    printf("  Success: relay_info_serialize_buffer_too_small\n");
    test_relay_info_serialize_null_fields_omitted();
    printf("  Success: relay_info_serialize_null_fields_omitted\n");
    test_relay_info_serialize_with_fees();
    printf("  Success: relay_info_serialize_with_fees\n");
    test_relay_info_serialize_with_retention();
    printf("  Success: relay_info_serialize_with_retention\n");
#else
    printf("  (NIP-11 serialization tests skipped - NOSTR_FEATURE_JSON_ENHANCED not enabled)\n");
#endif

    /* Tag Iteration tests */
    printf("  Running tag iteration tests...\n");

    test_tag_iterator_basic();
    printf("  Success: tag_iterator_basic\n");
    test_tag_iterator_next_info();
    printf("  Success: tag_iterator_next_info\n");
    test_tag_iterator_empty_event();
    printf("  Success: tag_iterator_empty_event\n");
    test_tag_is_indexable();
    printf("  Success: tag_is_indexable\n");

    /* Filter Tag Accessor tests */
    printf("  Running filter tag accessor tests...\n");

    test_filter_get_e_tags();
    printf("  Success: filter_get_e_tags\n");
    test_filter_get_p_tags();
    printf("  Success: filter_get_p_tags\n");
    test_filter_get_tag_values_generic();
    printf("  Success: filter_get_tag_values_generic\n");
    test_filter_get_tag_values_not_found();
    printf("  Success: filter_get_tag_values_not_found\n");
    test_filter_has_tag_filters();
    printf("  Success: filter_has_tag_filters\n");
    test_filter_has_tag_filters_null();
    printf("  Success: filter_has_tag_filters_null\n");

    printf("All relay protocol tests passed!\n");
}

/* ============================================================
 * Accessor Function Tests
 * ============================================================ */

void test_nostr_hex_to_bytes(void)
{
    uint8_t out[32];
    nostr_relay_error_t err;

    /* Valid 64-char hex to 32 bytes */
    err = nostr_hex_to_bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 64, out, 32);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(0x01, out[0]);
    TEST_ASSERT_EQUAL(0x23, out[1]);
    TEST_ASSERT_EQUAL(0xef, out[31]);

    /* Invalid hex character */
    err = nostr_hex_to_bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg", 64, out, 32);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_ID, err);

    /* Odd length */
    err = nostr_hex_to_bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", 63, out, 32);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_ID, err);

    /* Buffer too small */
    err = nostr_hex_to_bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 64, out, 31);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_BUFFER_TOO_SMALL, err);

    /* NULL parameters */
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

    /* Empty input */
    nostr_bytes_to_hex(bytes, 0, out);
    TEST_ASSERT_EQUAL_STRING("", out);
}

void test_nostr_version(void)
{
    const char* version = nostr_version();
    TEST_ASSERT_NOT_NULL(version);
    /* Version should be non-empty string */
    TEST_ASSERT_TRUE(strlen(version) > 0);
}

void test_nostr_free(void)
{
    /* Just verify it doesn't crash */
    char* ptr = malloc(10);
    nostr_free(ptr);
    nostr_free(NULL); /* Should handle NULL gracefully */
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

    /* Test get_ids */
    size_t count = 0;
    const char** ids = nostr_filter_get_ids(&filter, &count);
    TEST_ASSERT_NOT_NULL(ids);
    TEST_ASSERT_EQUAL(1, count);
    TEST_ASSERT_EQUAL_STRING("abc123", ids[0]);

    /* Test get_authors */
    const char** authors = nostr_filter_get_authors(&filter, &count);
    TEST_ASSERT_NOT_NULL(authors);
    TEST_ASSERT_EQUAL(1, count);
    TEST_ASSERT_EQUAL_STRING("def456", authors[0]);

    /* Test get_kinds */
    const int32_t* kinds = nostr_filter_get_kinds(&filter, &count);
    TEST_ASSERT_NOT_NULL(kinds);
    TEST_ASSERT_EQUAL(3, count);
    TEST_ASSERT_EQUAL(1, kinds[0]);
    TEST_ASSERT_EQUAL(2, kinds[1]);
    TEST_ASSERT_EQUAL(3, kinds[2]);

    /* Test get_since/until/limit */
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

    /* Add tags */
    const char* e_tag[] = {"e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36"};
    const char* p_tag[] = {"p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca"};
    const char* d_tag[] = {"d", "my-article", "extra-value"};

    nostr_event_add_tag(event, e_tag, 2);
    nostr_event_add_tag(event, p_tag, 2);
    nostr_event_add_tag(event, d_tag, 3);

    /* Test get_tag_count */
    TEST_ASSERT_EQUAL(3, nostr_event_get_tag_count(event));

    /* Test get_tag */
    const nostr_tag* tag = nostr_event_get_tag(event, 0);
    TEST_ASSERT_NOT_NULL(tag);

    /* Test tag accessors - note: tag->count includes tag name at index 0 */
    TEST_ASSERT_EQUAL_STRING("e", nostr_tag_get_name(tag));
    TEST_ASSERT_EQUAL(2, nostr_tag_get_value_count(tag)); /* ["e", "hex..."] = 2 items */
    TEST_ASSERT_EQUAL_STRING("e", nostr_tag_get_value(tag, 0)); /* index 0 is tag name */
    TEST_ASSERT_EQUAL_STRING("5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", nostr_tag_get_value(tag, 1));
    TEST_ASSERT_NULL(nostr_tag_get_value(tag, 2)); /* Out of bounds */

    /* Test d tag with multiple values - ["d", "my-article", "extra-value"] = 3 items */
    const nostr_tag* d_tag_ptr = nostr_event_get_tag(event, 2);
    TEST_ASSERT_NOT_NULL(d_tag_ptr);
    TEST_ASSERT_EQUAL_STRING("d", nostr_tag_get_name(d_tag_ptr));
    TEST_ASSERT_EQUAL(3, nostr_tag_get_value_count(d_tag_ptr)); /* ["d", "my-article", "extra-value"] */
    TEST_ASSERT_EQUAL_STRING("d", nostr_tag_get_value(d_tag_ptr, 0)); /* index 0 is tag name */
    TEST_ASSERT_EQUAL_STRING("my-article", nostr_tag_get_value(d_tag_ptr, 1));
    TEST_ASSERT_EQUAL_STRING("extra-value", nostr_tag_get_value(d_tag_ptr, 2));

    /* Test find_tag */
    const nostr_tag* found = nostr_event_find_tag(event, "p");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("p", nostr_tag_get_name(found));

    TEST_ASSERT_NULL(nostr_event_find_tag(event, "x")); /* Not found */

    /* Test out of bounds */
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

    /* Regular event is not a deletion */
    event->kind = 1;
    TEST_ASSERT_FALSE(nostr_event_is_deletion(event));

    /* Kind 5 is a deletion event */
    event->kind = 5;
    TEST_ASSERT_TRUE(nostr_event_is_deletion(event));

    /* NULL handling */
    TEST_ASSERT_FALSE(nostr_event_is_deletion(NULL));

    nostr_event_destroy(event);
}

void test_event_binary_tag_extractors(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    /* Add e and p tags with valid hex */
    const char* e_tag1[] = {"e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36"};
    const char* e_tag2[] = {"e", "0000000000000000000000000000000000000000000000000000000000000001"};
    const char* p_tag[] = {"p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca"};
    const char* d_tag[] = {"d", "not-a-binary-tag"};

    nostr_event_add_tag(event, e_tag1, 2);
    nostr_event_add_tag(event, e_tag2, 2);
    nostr_event_add_tag(event, p_tag, 2);
    nostr_event_add_tag(event, d_tag, 2);

    /* Test e-tag extraction */
    size_t count = 0;
    uint8_t (*e_tags)[32] = nostr_event_get_e_tags_binary(event, &count);
    TEST_ASSERT_NOT_NULL(e_tags);
    TEST_ASSERT_EQUAL(2, count);
    /* Verify first byte of first e-tag */
    TEST_ASSERT_EQUAL(0x5c, e_tags[0][0]);
    /* Verify last byte of second e-tag */
    TEST_ASSERT_EQUAL(0x01, e_tags[1][31]);
    free(e_tags);

    /* Test p-tag extraction */
    uint8_t (*p_tags)[32] = nostr_event_get_p_tags_binary(event, &count);
    TEST_ASSERT_NOT_NULL(p_tags);
    TEST_ASSERT_EQUAL(1, count);
    TEST_ASSERT_EQUAL(0xf7, p_tags[0][0]);
    free(p_tags);

    /* NULL handling */
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

void run_new_accessor_tests(void)
{
    printf("  Running new accessor function tests...\n");

    test_nostr_hex_to_bytes();
    printf("  Success: nostr_hex_to_bytes\n");
    test_nostr_bytes_to_hex();
    printf("  Success: nostr_bytes_to_hex\n");
    test_nostr_version();
    printf("  Success: nostr_version\n");
    test_nostr_free();
    printf("  Success: nostr_free\n");
    test_nostr_free_strings();
    printf("  Success: nostr_free_strings\n");
    test_filter_accessors();
    printf("  Success: filter_accessors\n");
    test_filter_accessors_null();
    printf("  Success: filter_accessors_null\n");
    test_client_msg_accessors();
    printf("  Success: client_msg_accessors\n");
    test_client_msg_accessors_null();
    printf("  Success: client_msg_accessors_null\n");
    test_event_accessors();
    printf("  Success: event_accessors\n");
    test_event_accessors_null();
    printf("  Success: event_accessors_null\n");
    test_event_is_deletion();
    printf("  Success: event_is_deletion\n");
    test_event_binary_tag_extractors();
    printf("  Success: event_binary_tag_extractors\n");
    test_event_binary_tag_extractors_no_tags();
    printf("  Success: event_binary_tag_extractors_no_tags\n");

    printf("  All new accessor tests passed!\n");
}

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    nostr_init();
    run_relay_protocol_tests();
    run_new_accessor_tests();
    nostr_cleanup();
    return 0;
}
#endif
