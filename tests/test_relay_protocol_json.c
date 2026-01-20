/**
 * @file test_relay_protocol_json.c
 * @brief JSON-dependent tests: filters, client messages, event serialization
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

int run_relay_protocol_json_tests(void)
{
#ifndef HAVE_UNITY
    g_tests_failed_count = 0;
#endif

    printf("Running relay protocol JSON tests...\n");

#ifdef HAVE_UNITY
    RUN_TEST(test_filter_parse_empty);
    RUN_TEST(test_filter_parse_kinds);
    RUN_TEST(test_filter_parse_authors);
    RUN_TEST(test_filter_parse_since_until_limit);
    RUN_TEST(test_filter_parse_tags);
    RUN_TEST(test_filter_parse_invalid_json);
    RUN_TEST(test_filter_matches_empty_filter);
    RUN_TEST(test_filter_matches_kind);
    RUN_TEST(test_filter_matches_since_until);
    RUN_TEST(test_filter_matches_e_tags);
    RUN_TEST(test_filters_match_or_logic);
    RUN_TEST(test_client_msg_parse_close);
    RUN_TEST(test_client_msg_parse_req);
    RUN_TEST(test_client_msg_parse_req_multiple_filters);
    RUN_TEST(test_client_msg_parse_invalid_json);
    RUN_TEST(test_client_msg_parse_unknown_type);
    RUN_TEST(test_relay_msg_serialize_ok);
    RUN_TEST(test_relay_msg_serialize_eose);
    RUN_TEST(test_relay_msg_serialize_notice);
    RUN_TEST(test_relay_msg_serialize_buffer_too_small);
    RUN_TEST(test_event_parse_valid);
    RUN_TEST(test_event_parse_invalid_json);
    RUN_TEST(test_event_parse_null_params);
    RUN_TEST(test_event_serialize_valid);
    RUN_TEST(test_event_serialize_buffer_too_small);
    RUN_TEST(test_event_serialize_canonical_format);
    RUN_TEST(test_event_serialize_canonical_with_tags);
    RUN_TEST(test_event_serialize_canonical_escaping);
    RUN_TEST(test_event_serialize_canonical_buffer_too_small);
    RUN_TEST(test_filter_get_e_tags);
    RUN_TEST(test_filter_get_p_tags);
    RUN_TEST(test_filter_get_tag_values_generic);
    RUN_TEST(test_filter_get_tag_values_not_found);
    RUN_TEST(test_filter_has_tag_filters);
    RUN_TEST(test_filter_has_tag_filters_null);
#else
    RUN_TEST(test_filter_parse_empty, "filter_parse_empty");
    RUN_TEST(test_filter_parse_kinds, "filter_parse_kinds");
    RUN_TEST(test_filter_parse_authors, "filter_parse_authors");
    RUN_TEST(test_filter_parse_since_until_limit, "filter_parse_since_until_limit");
    RUN_TEST(test_filter_parse_tags, "filter_parse_tags");
    RUN_TEST(test_filter_parse_invalid_json, "filter_parse_invalid_json");
    RUN_TEST(test_filter_matches_empty_filter, "filter_matches_empty_filter");
    RUN_TEST(test_filter_matches_kind, "filter_matches_kind");
    RUN_TEST(test_filter_matches_since_until, "filter_matches_since_until");
    RUN_TEST(test_filter_matches_e_tags, "filter_matches_e_tags");
    RUN_TEST(test_filters_match_or_logic, "filters_match_or_logic");
    RUN_TEST(test_client_msg_parse_close, "client_msg_parse_close");
    RUN_TEST(test_client_msg_parse_req, "client_msg_parse_req");
    RUN_TEST(test_client_msg_parse_req_multiple_filters, "client_msg_parse_req_multiple_filters");
    RUN_TEST(test_client_msg_parse_invalid_json, "client_msg_parse_invalid_json");
    RUN_TEST(test_client_msg_parse_unknown_type, "client_msg_parse_unknown_type");
    RUN_TEST(test_relay_msg_serialize_ok, "relay_msg_serialize_ok");
    RUN_TEST(test_relay_msg_serialize_eose, "relay_msg_serialize_eose");
    RUN_TEST(test_relay_msg_serialize_notice, "relay_msg_serialize_notice");
    RUN_TEST(test_relay_msg_serialize_buffer_too_small, "relay_msg_serialize_buffer_too_small");
    RUN_TEST(test_event_parse_valid, "event_parse_valid");
    RUN_TEST(test_event_parse_invalid_json, "event_parse_invalid_json");
    RUN_TEST(test_event_parse_null_params, "event_parse_null_params");
    RUN_TEST(test_event_serialize_valid, "event_serialize_valid");
    RUN_TEST(test_event_serialize_buffer_too_small, "event_serialize_buffer_too_small");
    RUN_TEST(test_event_serialize_canonical_format, "event_serialize_canonical_format");
    RUN_TEST(test_event_serialize_canonical_with_tags, "event_serialize_canonical_with_tags");
    RUN_TEST(test_event_serialize_canonical_escaping, "event_serialize_canonical_escaping");
    RUN_TEST(test_event_serialize_canonical_buffer_too_small, "event_serialize_canonical_buffer_too_small");
    RUN_TEST(test_filter_get_e_tags, "filter_get_e_tags");
    RUN_TEST(test_filter_get_p_tags, "filter_get_p_tags");
    RUN_TEST(test_filter_get_tag_values_generic, "filter_get_tag_values_generic");
    RUN_TEST(test_filter_get_tag_values_not_found, "filter_get_tag_values_not_found");
    RUN_TEST(test_filter_has_tag_filters, "filter_has_tag_filters");
    RUN_TEST(test_filter_has_tag_filters_null, "filter_has_tag_filters_null");
#endif

#ifndef HAVE_UNITY
    if (g_tests_failed_count > 0) {
        printf("FAILED: %d test(s) failed!\n", g_tests_failed_count);
        return g_tests_failed_count;
    }
#endif
    printf("All relay protocol JSON tests passed!\n");
    return 0;
}

#else

int run_relay_protocol_json_tests(void)
{
    printf("Relay protocol JSON tests skipped (NOSTR_FEATURE_JSON_ENHANCED not enabled)\n");
    return 0;
}

#endif

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    nostr_init();
    int result = run_relay_protocol_json_tests();
    nostr_cleanup();
    return result;
}
#endif
