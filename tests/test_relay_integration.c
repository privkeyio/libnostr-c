/**
 * @file test_relay_integration.c
 * @brief Integration tests simulating actual relay workflows
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/nostr.h"
#include "../include/nostr_relay_protocol.h"

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("  FAIL: %s\n", msg); \
            return 0; \
        } \
    } while(0)

#define TEST_ASSERT_EQ(expected, actual, msg) \
    do { \
        if ((expected) != (actual)) { \
            printf("  FAIL: %s (expected %d, got %d)\n", msg, (int)(expected), (int)(actual)); \
            return 0; \
        } \
    } while(0)

#define TEST_ASSERT_STR_EQ(expected, actual, msg) \
    do { \
        if (strcmp(expected, actual) != 0) { \
            printf("  FAIL: %s (expected '%s', got '%s')\n", msg, expected, actual); \
            return 0; \
        } \
    } while(0)

static int test_relay_workflow_event_submission(void);
static int test_relay_workflow_subscription(void);
static int test_relay_workflow_close_subscription(void);
static int test_relay_workflow_replaceable_event(void);
static int test_relay_workflow_addressable_event(void);
static int test_relay_workflow_ephemeral_event(void);
static int test_relay_workflow_expired_event(void);
static int test_relay_workflow_notice(void);

#ifdef NOSTR_FEATURE_JSON_ENHANCED
static int test_relay_full_flow_with_json(void);
#endif

static int test_relay_workflow_event_submission(void)
{
    printf("  Testing: Event submission workflow...\n");

    nostr_event* event = NULL;
    TEST_ASSERT_EQ(NOSTR_OK, nostr_event_create(&event), "Event creation failed");

    event->kind = 1;
    event->created_at = nostr_timestamp_now();
    nostr_event_set_content(event, "Hello, Nostr!");

    const char* test_pubkey = "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca";
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        sscanf(&test_pubkey[i * 2], "%02x", &byte);
        event->pubkey.data[i] = (unsigned char)byte;
    }

    const char* t_tag[] = {"t", "nostr"};
    nostr_event_add_tag(event, t_tag, 2);

    TEST_ASSERT(nostr_validate_timestamp(event->created_at, 900),
                "Event timestamp validation failed");

    nostr_kind_type_t kind_type = nostr_kind_get_type(event->kind);
    TEST_ASSERT_EQ(NOSTR_KIND_REGULAR, kind_type, "Kind should be REGULAR");

    nostr_relay_msg_t ok_msg;
    char event_id_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&event_id_hex[i * 2], "%02x", event->id[i]);
    }
    event_id_hex[64] = '\0';

    nostr_relay_msg_ok(&ok_msg, event_id_hex, true, "");
    TEST_ASSERT_EQ(NOSTR_RELAY_MSG_OK, ok_msg.type, "Message type should be OK");
    TEST_ASSERT(ok_msg.data.ok.success, "OK message should indicate success");

    nostr_relay_msg_t reject_msg;
    nostr_relay_msg_ok(&reject_msg, event_id_hex, false,
                       NOSTR_OK_PREFIX_BLOCKED "you are not allowed to post here");
    TEST_ASSERT(!reject_msg.data.ok.success, "Rejection should indicate failure");
    TEST_ASSERT(strstr(reject_msg.data.ok.message, "blocked:") != NULL,
                "Rejection message should contain 'blocked:'");

    nostr_event_destroy(event);
    printf("  PASS: Event submission workflow\n");
    return 1;
}

static int test_relay_workflow_subscription(void)
{
    printf("  Testing: Subscription workflow...\n");

    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    int32_t kinds[] = {1};
    filter.kinds = kinds;
    filter.kinds_count = 1;
    filter.since = 1700000000;
    filter.limit = 100;

    nostr_event* event1 = NULL;
    nostr_event* event2 = NULL;
    nostr_event* event3 = NULL;

    nostr_event_create(&event1);
    nostr_event_create(&event2);
    nostr_event_create(&event3);

    event1->kind = 1;
    event1->created_at = 1700000001;

    event2->kind = 1;
    event2->created_at = 1600000000;

    event3->kind = 7;
    event3->created_at = 1700000001;

    TEST_ASSERT(nostr_filter_matches(&filter, event1), "Event1 should match filter");
    TEST_ASSERT(!nostr_filter_matches(&filter, event2), "Event2 should NOT match (too old)");
    TEST_ASSERT(!nostr_filter_matches(&filter, event3), "Event3 should NOT match (wrong kind)");

    nostr_relay_msg_t event_msg;
    nostr_relay_msg_event(&event_msg, "sub-123", event1);
    TEST_ASSERT_EQ(NOSTR_RELAY_MSG_EVENT, event_msg.type, "Message type should be EVENT");
    TEST_ASSERT_STR_EQ("sub-123", event_msg.data.event.subscription_id, "Subscription ID mismatch");
    TEST_ASSERT(event_msg.data.event.event == event1, "Event pointer mismatch");

    nostr_relay_msg_t eose_msg;
    nostr_relay_msg_eose(&eose_msg, "sub-123");
    TEST_ASSERT_EQ(NOSTR_RELAY_MSG_EOSE, eose_msg.type, "Message type should be EOSE");
    TEST_ASSERT_STR_EQ("sub-123", eose_msg.data.eose.subscription_id, "Subscription ID mismatch");

    nostr_event_destroy(event1);
    nostr_event_destroy(event2);
    nostr_event_destroy(event3);

    printf("  PASS: Subscription workflow\n");
    return 1;
}

static int test_relay_workflow_close_subscription(void)
{
    printf("  Testing: Close subscription workflow...\n");

    const char* sub_id = "my-subscription-123";
    TEST_ASSERT(nostr_validate_subscription_id(sub_id), "Subscription ID should be valid");
    TEST_ASSERT(!nostr_validate_subscription_id(""), "Empty subscription ID should be invalid");
    TEST_ASSERT(!nostr_validate_subscription_id(NULL), "NULL subscription ID should be invalid");

    nostr_relay_msg_t closed_msg;
    nostr_relay_msg_closed(&closed_msg, sub_id, "");
    TEST_ASSERT_EQ(NOSTR_RELAY_MSG_CLOSED, closed_msg.type, "Message type should be CLOSED");
    TEST_ASSERT_STR_EQ(sub_id, closed_msg.data.closed.subscription_id, "Subscription ID mismatch");

    nostr_relay_msg_t timeout_msg;
    nostr_relay_msg_closed(&timeout_msg, sub_id, "error: idle subscription closed");
    TEST_ASSERT(strstr(timeout_msg.data.closed.message, "error:") != NULL,
                "Should contain error message");

    printf("  PASS: Close subscription workflow\n");
    return 1;
}

static int test_relay_workflow_replaceable_event(void)
{
    printf("  Testing: Replaceable event workflow...\n");

    TEST_ASSERT(nostr_kind_is_replaceable(0), "Kind 0 should be replaceable");
    TEST_ASSERT(nostr_kind_is_replaceable(3), "Kind 3 should be replaceable");
    TEST_ASSERT(nostr_kind_is_replaceable(10000), "Kind 10000 should be replaceable");
    TEST_ASSERT(nostr_kind_is_replaceable(19999), "Kind 19999 should be replaceable");
    TEST_ASSERT(!nostr_kind_is_replaceable(1), "Kind 1 should NOT be replaceable");

    nostr_event* older_event = NULL;
    nostr_event* newer_event = NULL;

    nostr_event_create(&older_event);
    nostr_event_create(&newer_event);

    older_event->kind = 0;
    older_event->created_at = 1700000000;
    memset(older_event->pubkey.data, 0xAA, 32);

    newer_event->kind = 0;
    newer_event->created_at = 1700000001;
    memset(newer_event->pubkey.data, 0xAA, 32);

    int cmp = nostr_event_compare_replaceable(older_event, newer_event);
    TEST_ASSERT(cmp < 0, "Older event should compare less than newer");

    cmp = nostr_event_compare_replaceable(newer_event, older_event);
    TEST_ASSERT(cmp > 0, "Newer event should compare greater than older");

    newer_event->created_at = older_event->created_at;
    memset(older_event->id, 0x00, 32);
    memset(newer_event->id, 0xFF, 32);

    cmp = nostr_event_compare_replaceable(older_event, newer_event);
    TEST_ASSERT(cmp > 0, "Lower ID should win when timestamps are equal");

    nostr_event_destroy(older_event);
    nostr_event_destroy(newer_event);

    printf("  PASS: Replaceable event workflow\n");
    return 1;
}

static int test_relay_workflow_addressable_event(void)
{
    printf("  Testing: Addressable event workflow...\n");

    TEST_ASSERT(nostr_kind_is_addressable(30000), "Kind 30000 should be addressable");
    TEST_ASSERT(nostr_kind_is_addressable(30023), "Kind 30023 (long-form) should be addressable");
    TEST_ASSERT(nostr_kind_is_addressable(39999), "Kind 39999 should be addressable");
    TEST_ASSERT(!nostr_kind_is_addressable(29999), "Kind 29999 should NOT be addressable");

    nostr_event* event = NULL;
    nostr_event_create(&event);

    event->kind = 30023;
    event->created_at = nostr_timestamp_now();

    const char* d_tag[] = {"d", "my-article-slug"};
    nostr_event_add_tag(event, d_tag, 2);

    const char* d_value = nostr_event_get_d_tag(event);
    TEST_ASSERT(d_value != NULL, "D-tag should exist");
    TEST_ASSERT_STR_EQ("my-article-slug", d_value, "D-tag value mismatch");

    nostr_event* no_d_event = NULL;
    nostr_event_create(&no_d_event);
    no_d_event->kind = 30023;

    const char* no_d_value = nostr_event_get_d_tag(no_d_event);
    TEST_ASSERT(no_d_value == NULL, "Event without d-tag should return NULL");

    nostr_event_destroy(event);
    nostr_event_destroy(no_d_event);

    printf("  PASS: Addressable event workflow\n");
    return 1;
}

static int test_relay_workflow_ephemeral_event(void)
{
    printf("  Testing: Ephemeral event workflow...\n");

    TEST_ASSERT(nostr_kind_is_ephemeral(20000), "Kind 20000 should be ephemeral");
    TEST_ASSERT(nostr_kind_is_ephemeral(25000), "Kind 25000 should be ephemeral");
    TEST_ASSERT(nostr_kind_is_ephemeral(29999), "Kind 29999 should be ephemeral");
    TEST_ASSERT(!nostr_kind_is_ephemeral(19999), "Kind 19999 should NOT be ephemeral");
    TEST_ASSERT(!nostr_kind_is_ephemeral(30000), "Kind 30000 should NOT be ephemeral");

    nostr_event* event = NULL;
    nostr_event_create(&event);
    event->kind = 24133;

    bool should_store = !nostr_kind_is_ephemeral(event->kind);
    TEST_ASSERT(!should_store, "Ephemeral events should NOT be stored");

    nostr_event_destroy(event);

    printf("  PASS: Ephemeral event workflow\n");
    return 1;
}

static int test_relay_workflow_expired_event(void)
{
    printf("  Testing: Expired event workflow...\n");

    nostr_event* expired_event = NULL;
    nostr_event_create(&expired_event);
    expired_event->kind = 1;
    expired_event->created_at = 1700000000;

    const char* exp_tag[] = {"expiration", "1700000001"};
    nostr_event_add_tag(expired_event, exp_tag, 2);

    int64_t expiration = nostr_event_get_expiration(expired_event);
    TEST_ASSERT_EQ(1700000001, expiration, "Expiration timestamp mismatch");
    TEST_ASSERT(nostr_event_is_expired_now(expired_event), "Event should be expired");

    if (nostr_event_is_expired_now(expired_event)) {
        nostr_relay_msg_t reject_msg;
        char event_id_hex[65] = {0};
        for (int i = 0; i < 32; i++) {
            sprintf(&event_id_hex[i * 2], "%02x", expired_event->id[i]);
        }
        nostr_relay_msg_ok(&reject_msg, event_id_hex, false,
                           NOSTR_OK_PREFIX_INVALID "event has expired");
        TEST_ASSERT(!reject_msg.data.ok.success, "Expired event should be rejected");
        TEST_ASSERT(strstr(reject_msg.data.ok.message, "invalid:") != NULL,
                    "Rejection should use 'invalid:' prefix");
    }

    nostr_event* future_event = NULL;
    nostr_event_create(&future_event);
    future_event->kind = 1;
    future_event->created_at = nostr_timestamp_now();

    char future_exp[32];
    snprintf(future_exp, sizeof(future_exp), "%lld",
             (long long)(nostr_timestamp_now() + 3600));
    const char* future_tag[] = {"expiration", future_exp};
    nostr_event_add_tag(future_event, future_tag, 2);

    TEST_ASSERT(!nostr_event_is_expired_now(future_event), "Future event should NOT be expired");

    nostr_event_destroy(expired_event);
    nostr_event_destroy(future_event);

    printf("  PASS: Expired event workflow\n");
    return 1;
}

static int test_relay_workflow_notice(void)
{
    printf("  Testing: NOTICE message workflow...\n");

    nostr_relay_msg_t welcome;
    nostr_relay_msg_notice(&welcome, "Welcome to the relay! Please read our ToS.");
    TEST_ASSERT_EQ(NOSTR_RELAY_MSG_NOTICE, welcome.type, "Message type should be NOTICE");
    TEST_ASSERT(strstr(welcome.data.notice.message, "Welcome") != NULL,
                "Notice should contain welcome message");

    nostr_relay_msg_t rate_limit;
    nostr_relay_msg_notice(&rate_limit, "rate-limited: too many requests, please slow down");
    TEST_ASSERT(strstr(rate_limit.data.notice.message, "rate-limited") != NULL,
                "Notice should contain rate-limit message");

    const char* error_str = nostr_relay_error_string(NOSTR_RELAY_ERR_INVALID_JSON);
    TEST_ASSERT(strcmp(error_str, "invalid JSON") == 0, "Error string mismatch");

    error_str = nostr_relay_error_string(NOSTR_RELAY_ERR_SIG_MISMATCH);
    TEST_ASSERT(strcmp(error_str, "signature verification failed") == 0, "Error string mismatch");

    printf("  PASS: NOTICE message workflow\n");
    return 1;
}

#ifdef NOSTR_FEATURE_JSON_ENHANCED
static int test_relay_full_flow_with_json(void)
{
    printf("  Testing: Full relay flow with JSON...\n");

    const char* close_json = "[\"CLOSE\",\"test-sub-1\"]";
    nostr_client_msg_t close_msg;
    nostr_relay_error_t err = nostr_client_msg_parse(close_json, strlen(close_json), &close_msg);
    TEST_ASSERT_EQ(NOSTR_RELAY_OK, err, "CLOSE parsing failed");
    TEST_ASSERT_EQ(NOSTR_CLIENT_MSG_CLOSE, close_msg.type, "Message type should be CLOSE");
    TEST_ASSERT_STR_EQ("test-sub-1", close_msg.data.close.subscription_id, "Subscription ID mismatch");
    nostr_client_msg_free(&close_msg);

    const char* req_json = "[\"REQ\",\"sub-abc\",{\"kinds\":[1,7],\"since\":1700000000,\"limit\":50}]";
    nostr_client_msg_t req_msg;
    err = nostr_client_msg_parse(req_json, strlen(req_json), &req_msg);
    TEST_ASSERT_EQ(NOSTR_RELAY_OK, err, "REQ parsing failed");
    TEST_ASSERT_EQ(NOSTR_CLIENT_MSG_REQ, req_msg.type, "Message type should be REQ");
    TEST_ASSERT_STR_EQ("sub-abc", req_msg.data.req.subscription_id, "Subscription ID mismatch");
    TEST_ASSERT_EQ(1, req_msg.data.req.filters_count, "Should have 1 filter");
    TEST_ASSERT_EQ(2, req_msg.data.req.filters[0].kinds_count, "Filter should have 2 kinds");
    TEST_ASSERT_EQ(50, req_msg.data.req.filters[0].limit, "Filter limit mismatch");

    nostr_event* event = NULL;
    nostr_event_create(&event);
    event->kind = 1;
    event->created_at = 1700000001;

    bool matches = nostr_filter_matches(&req_msg.data.req.filters[0], event);
    TEST_ASSERT(matches, "Event should match filter");

    nostr_relay_msg_t ok_msg;
    nostr_relay_msg_ok(&ok_msg, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                       true, "");

    char buf[512];
    size_t len;
    err = nostr_relay_msg_serialize(&ok_msg, buf, sizeof(buf), &len);
    TEST_ASSERT_EQ(NOSTR_RELAY_OK, err, "OK serialization failed");
    TEST_ASSERT(strstr(buf, "\"OK\"") != NULL, "Serialized message should contain 'OK'");
    TEST_ASSERT(strstr(buf, "true") != NULL, "Serialized message should contain 'true'");

    nostr_relay_msg_t eose_msg;
    nostr_relay_msg_eose(&eose_msg, "sub-abc");

    err = nostr_relay_msg_serialize(&eose_msg, buf, sizeof(buf), &len);
    TEST_ASSERT_EQ(NOSTR_RELAY_OK, err, "EOSE serialization failed");
    TEST_ASSERT(strstr(buf, "\"EOSE\"") != NULL, "Serialized message should contain 'EOSE'");
    TEST_ASSERT(strstr(buf, "\"sub-abc\"") != NULL, "Serialized message should contain subscription ID");

    nostr_relay_msg_t closed_msg;
    nostr_relay_msg_closed(&closed_msg, "sub-abc", "error: subscription timeout");

    err = nostr_relay_msg_serialize(&closed_msg, buf, sizeof(buf), &len);
    TEST_ASSERT_EQ(NOSTR_RELAY_OK, err, "CLOSED serialization failed");
    TEST_ASSERT(strstr(buf, "\"CLOSED\"") != NULL, "Serialized message should contain 'CLOSED'");

    nostr_event_destroy(event);
    nostr_client_msg_free(&req_msg);

    printf("  PASS: Full relay flow with JSON\n");
    return 1;
}
#endif

int main(void)
{
    int passed = 0;
    int failed = 0;

    printf("\n=== Relay Integration Tests ===\n\n");

    nostr_init();

    if (test_relay_workflow_event_submission()) passed++; else failed++;
    if (test_relay_workflow_subscription()) passed++; else failed++;
    if (test_relay_workflow_close_subscription()) passed++; else failed++;
    if (test_relay_workflow_replaceable_event()) passed++; else failed++;
    if (test_relay_workflow_addressable_event()) passed++; else failed++;
    if (test_relay_workflow_ephemeral_event()) passed++; else failed++;
    if (test_relay_workflow_expired_event()) passed++; else failed++;
    if (test_relay_workflow_notice()) passed++; else failed++;

#ifdef NOSTR_FEATURE_JSON_ENHANCED
    printf("\n  Running JSON-enabled integration tests...\n\n");
    if (test_relay_full_flow_with_json()) passed++; else failed++;
#else
    printf("\n  (JSON tests skipped - NOSTR_FEATURE_JSON_ENHANCED not enabled)\n");
#endif

    printf("\n=== Results: %d passed, %d failed ===\n\n", passed, failed);

    nostr_cleanup();

    return failed > 0 ? 1 : 0;
}
