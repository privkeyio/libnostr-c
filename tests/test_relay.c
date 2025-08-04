#include "unity.h"
#include "nostr.h"
#include "nostr_features.h"
#include <string.h>
#include <stdlib.h>

#ifdef NOSTR_FEATURE_RELAY

static nostr_event* received_event = NULL;
static char* received_message_type = NULL;
static char* received_message_data = NULL;
static int callback_count = 0;

static void test_event_callback(const nostr_event* event, void* user_data) {
    callback_count++;
    if (received_event) {
        nostr_event_destroy(received_event);
    }
    nostr_event_create(&received_event);
    if (received_event && event) {
        memcpy(received_event->id, event->id, NOSTR_ID_SIZE);
        received_event->pubkey = event->pubkey;
        received_event->created_at = event->created_at;
        received_event->kind = event->kind;
        if (event->content) {
            received_event->content = strdup(event->content);
        }
    }
}

static void test_message_callback(const char* message_type, const char* data, void* user_data) {
    callback_count++;
    free(received_message_type);
    free(received_message_data);
    received_message_type = strdup(message_type);
    received_message_data = strdup(data);
}

static void reset_test_state(void) {
    callback_count = 0;
    if (received_event) {
        nostr_event_destroy(received_event);
        received_event = NULL;
    }
    free(received_message_type);
    free(received_message_data);
    received_message_type = NULL;
    received_message_data = NULL;
}

void test_relay_create_destroy(void) {
    nostr_relay* relay = NULL;
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_relay_create(NULL, "wss://test.com"));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_relay_create(&relay, NULL));
    
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_create(&relay, "wss://relay.test.com"));
    TEST_ASSERT_NOT_NULL(relay);
    TEST_ASSERT_EQUAL_STRING("wss://relay.test.com", relay->url);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_DISCONNECTED, relay->state);
    
    nostr_relay_destroy(relay);
}

void test_subscribe_parameters(void) {
    nostr_relay* relay = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_create(&relay, "wss://test.com"));
    
    const char* filters = "{\"kinds\":[1]}";
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, 
                     nostr_subscribe(NULL, "sub1", filters, test_event_callback, NULL));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, 
                     nostr_subscribe(relay, NULL, filters, test_event_callback, NULL));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, 
                     nostr_subscribe(relay, "sub1", NULL, test_event_callback, NULL));
    
    relay->state = NOSTR_RELAY_DISCONNECTED;
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, 
                     nostr_subscribe(relay, "sub1", filters, test_event_callback, NULL));
    
    nostr_relay_destroy(relay);
}

void test_publish_event_parameters(void) {
    nostr_relay* relay = NULL;
    nostr_event* event = NULL;
    
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_create(&relay, "wss://test.com"));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_publish_event(NULL, event));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_publish_event(relay, NULL));
    
    relay->state = NOSTR_RELAY_DISCONNECTED;
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_publish_event(relay, event));
    
    nostr_event_destroy(event);
    nostr_relay_destroy(relay);
}

void test_unsubscribe_parameters(void) {
    nostr_relay* relay = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_create(&relay, "wss://test.com"));
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_relay_unsubscribe(NULL, "sub1"));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_relay_unsubscribe(relay, NULL));
    
    relay->state = NOSTR_RELAY_DISCONNECTED;
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_relay_unsubscribe(relay, "sub1"));
    
    nostr_relay_destroy(relay);
}

void test_message_callback_setup(void) {
    nostr_relay* relay = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_relay_create(&relay, "wss://test.com"));
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, 
                     nostr_relay_set_message_callback(NULL, test_message_callback, NULL));
    
    TEST_ASSERT_EQUAL(NOSTR_OK, 
                     nostr_relay_set_message_callback(relay, test_message_callback, NULL));
    
    nostr_relay_destroy(relay);
}

void run_relay_tests(void) {
    reset_test_state();
    
    printf("   Running relay protocol tests...\n");
    
    RUN_TEST(test_relay_create_destroy);
    RUN_TEST(test_subscribe_parameters);
    RUN_TEST(test_publish_event_parameters);
    RUN_TEST(test_unsubscribe_parameters);
    RUN_TEST(test_message_callback_setup);
    
    reset_test_state();
}

#else // NOSTR_FEATURE_RELAY

void run_relay_tests(void)
{
    printf("   Relay tests skipped (RELAY feature not enabled)\n");
}

#endif // NOSTR_FEATURE_RELAY