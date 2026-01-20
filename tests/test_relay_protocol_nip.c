/**
 * @file test_relay_protocol_nip.c
 * @brief NIP-specific tests: NIP-09 deletion, NIP-11 relay info
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
    nostr_deletion_request_t request = {0};
    nostr_event event = {0};

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

    nostr_relay_info_free(&info);
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

    nostr_relay_info_free(&info);
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

int run_relay_protocol_nip_tests(void)
{
#ifndef HAVE_UNITY
    g_tests_failed_count = 0;
#endif

    printf("Running relay protocol NIP tests...\n");

    printf("  Running NIP-09 deletion tests...\n");
#ifdef HAVE_UNITY
    RUN_TEST(test_deletion_parse_basic);
    RUN_TEST(test_deletion_parse_with_addresses);
    RUN_TEST(test_deletion_parse_invalid_kind);
    RUN_TEST(test_deletion_parse_null_params);
    RUN_TEST(test_deletion_authorized_same_pubkey);
    RUN_TEST(test_deletion_unauthorized_different_pubkey);
    RUN_TEST(test_deletion_unauthorized_event_not_listed);
    RUN_TEST(test_deletion_authorized_address);
    RUN_TEST(test_deletion_unauthorized_address_different_pubkey);
    RUN_TEST(test_deletion_unauthorized_address_non_addressable);
    RUN_TEST(test_deletion_free_null);
#else
    RUN_TEST(test_deletion_parse_basic, "deletion_parse_basic");
    RUN_TEST(test_deletion_parse_with_addresses, "deletion_parse_with_addresses");
    RUN_TEST(test_deletion_parse_invalid_kind, "deletion_parse_invalid_kind");
    RUN_TEST(test_deletion_parse_null_params, "deletion_parse_null_params");
    RUN_TEST(test_deletion_authorized_same_pubkey, "deletion_authorized_same_pubkey");
    RUN_TEST(test_deletion_unauthorized_different_pubkey, "deletion_unauthorized_different_pubkey");
    RUN_TEST(test_deletion_unauthorized_event_not_listed, "deletion_unauthorized_event_not_listed");
    RUN_TEST(test_deletion_authorized_address, "deletion_authorized_address");
    RUN_TEST(test_deletion_unauthorized_address_different_pubkey, "deletion_unauthorized_address_different_pubkey");
    RUN_TEST(test_deletion_unauthorized_address_non_addressable, "deletion_unauthorized_address_non_addressable");
    RUN_TEST(test_deletion_free_null, "deletion_free_null");
#endif

    printf("  Running NIP-11 relay information tests...\n");
#ifdef HAVE_UNITY
    RUN_TEST(test_relay_limitation_init);
    RUN_TEST(test_relay_info_init);
    RUN_TEST(test_relay_info_set_nips);
    RUN_TEST(test_relay_info_add_nip);
    RUN_TEST(test_relay_info_free);
    RUN_TEST(test_relay_info_free_null);
#else
    RUN_TEST(test_relay_limitation_init, "relay_limitation_init");
    RUN_TEST(test_relay_info_init, "relay_info_init");
    RUN_TEST(test_relay_info_set_nips, "relay_info_set_nips");
    RUN_TEST(test_relay_info_add_nip, "relay_info_add_nip");
    RUN_TEST(test_relay_info_free, "relay_info_free");
    RUN_TEST(test_relay_info_free_null, "relay_info_free_null");
#endif

#ifdef NOSTR_FEATURE_JSON_ENHANCED
    printf("  Running NIP-11 serialization tests...\n");
#ifdef HAVE_UNITY
    RUN_TEST(test_relay_limitation_serialize);
    RUN_TEST(test_relay_limitation_serialize_buffer_too_small);
    RUN_TEST(test_relay_info_serialize_minimal);
    RUN_TEST(test_relay_info_serialize_full);
    RUN_TEST(test_relay_info_serialize_with_countries_and_tags);
    RUN_TEST(test_relay_info_serialize_buffer_too_small);
    RUN_TEST(test_relay_info_serialize_null_fields_omitted);
    RUN_TEST(test_relay_info_serialize_with_fees);
    RUN_TEST(test_relay_info_serialize_with_retention);
#else
    RUN_TEST(test_relay_limitation_serialize, "relay_limitation_serialize");
    RUN_TEST(test_relay_limitation_serialize_buffer_too_small, "relay_limitation_serialize_buffer_too_small");
    RUN_TEST(test_relay_info_serialize_minimal, "relay_info_serialize_minimal");
    RUN_TEST(test_relay_info_serialize_full, "relay_info_serialize_full");
    RUN_TEST(test_relay_info_serialize_with_countries_and_tags, "relay_info_serialize_with_countries_and_tags");
    RUN_TEST(test_relay_info_serialize_buffer_too_small, "relay_info_serialize_buffer_too_small");
    RUN_TEST(test_relay_info_serialize_null_fields_omitted, "relay_info_serialize_null_fields_omitted");
    RUN_TEST(test_relay_info_serialize_with_fees, "relay_info_serialize_with_fees");
    RUN_TEST(test_relay_info_serialize_with_retention, "relay_info_serialize_with_retention");
#endif
#else
    printf("  (NIP-11 serialization tests skipped - NOSTR_FEATURE_JSON_ENHANCED not enabled)\n");
#endif

#ifndef HAVE_UNITY
    if (g_tests_failed_count > 0) {
        printf("FAILED: %d test(s) failed!\n", g_tests_failed_count);
        return g_tests_failed_count;
    }
#endif
    printf("All relay protocol NIP tests passed!\n");
    return 0;
}

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    nostr_init();
    int result = run_relay_protocol_nip_tests();
    nostr_cleanup();
    return result;
}
#endif
