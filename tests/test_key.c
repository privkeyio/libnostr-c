#include <stdio.h>
#include <string.h>
#include "../include/nostr.h"

#ifdef HAVE_UNITY
#include <unity.h>
#else
#define TEST_ASSERT_EQUAL(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("Assertion failed: %s != %s\n", #expected, #actual); \
            return; \
        } \
    } while(0)

#define TEST_ASSERT_EQUAL_MEMORY(expected, actual, len) \
    do { \
        if (memcmp(expected, actual, len) != 0) { \
            printf("Memory comparison failed\n"); \
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
#endif

void test_key_generation(void)
{
    // Initialize the library first
    nostr_init();
    
    nostr_privkey privkey;
    nostr_key pubkey;
    
    nostr_error_t result = nostr_key_generate(&privkey, &pubkey);
    TEST_ASSERT_EQUAL(NOSTR_OK, result);
    
    // Verify keys are not all zeros
    int all_zeros = 1;
    for (int i = 0; i < NOSTR_PRIVKEY_SIZE; i++) {
        if (privkey.data[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    TEST_ASSERT_TRUE(!all_zeros);
    
    all_zeros = 1;
    for (int i = 0; i < NOSTR_PUBKEY_SIZE; i++) {
        if (pubkey.data[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    TEST_ASSERT_TRUE(!all_zeros);
}

void test_event_signing_and_verification(void)
{
    nostr_privkey privkey;
    nostr_key pubkey;
    
    // Generate keypair
    nostr_error_t result = nostr_key_generate(&privkey, &pubkey);
    TEST_ASSERT_EQUAL(NOSTR_OK, result);
    
    // Create event
    nostr_event* event;
    result = nostr_event_create(&event);
    TEST_ASSERT_EQUAL(NOSTR_OK, result);
    TEST_ASSERT_NOT_NULL(event);
    
    // Set event properties
    event->kind = 1;
    result = nostr_event_set_content(event, "Hello, Nostr!");
    TEST_ASSERT_EQUAL(NOSTR_OK, result);
    
    // Add tags
    const char* tag_values[] = {"e", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"};
    result = nostr_event_add_tag(event, tag_values, 2);
    TEST_ASSERT_EQUAL(NOSTR_OK, result);
    
    // Sign event
    result = nostr_event_sign(event, &privkey);
    TEST_ASSERT_EQUAL(NOSTR_OK, result);
    
    // Verify signature is not all zeros
    int all_zeros = 1;
    for (int i = 0; i < NOSTR_SIG_SIZE; i++) {
        if (event->sig[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    TEST_ASSERT_TRUE(!all_zeros);
    
    // Verify public key matches
    TEST_ASSERT_EQUAL_MEMORY(pubkey.data, event->pubkey.data, NOSTR_PUBKEY_SIZE);
    
    // Verify event
    result = nostr_event_verify(event);
    TEST_ASSERT_EQUAL(NOSTR_OK, result);
    
    // Corrupt signature and verify it fails
    event->sig[0] ^= 0xFF;
    result = nostr_event_verify(event);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_SIGNATURE, result);
    
    // Restore signature
    event->sig[0] ^= 0xFF;
    
    // Corrupt event ID and verify it fails
    event->id[0] ^= 0xFF;
    result = nostr_event_verify(event);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, result);
    
    nostr_event_destroy(event);
}

void test_multiple_signatures(void)
{
    nostr_privkey privkey1, privkey2;
    nostr_key pubkey1, pubkey2;
    
    // Generate two keypairs
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_generate(&privkey1, &pubkey1));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_generate(&privkey2, &pubkey2));
    
    // Verify keys are different
    TEST_ASSERT_TRUE(memcmp(privkey1.data, privkey2.data, NOSTR_PRIVKEY_SIZE) != 0);
    TEST_ASSERT_TRUE(memcmp(pubkey1.data, pubkey2.data, NOSTR_PUBKEY_SIZE) != 0);
    
    // Create and sign event with first key
    nostr_event* event;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_set_content(event, "Test message"));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_sign(event, &privkey1));
    
    // Save first signature
    uint8_t sig1[NOSTR_SIG_SIZE];
    memcpy(sig1, event->sig, NOSTR_SIG_SIZE);
    
    // Sign with second key
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_sign(event, &privkey2));
    
    // Verify signatures are different (different keys produce different signatures)
    TEST_ASSERT_TRUE(memcmp(sig1, event->sig, NOSTR_SIG_SIZE) != 0);
    
    // Verify public key was updated
    TEST_ASSERT_EQUAL_MEMORY(pubkey2.data, event->pubkey.data, NOSTR_PUBKEY_SIZE);
    
    // Verify second signature is valid
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_verify(event));
    
    nostr_event_destroy(event);
}

void test_deterministic_event_ids(void)
{
    nostr_privkey privkey;
    nostr_key pubkey;
    
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_generate(&privkey, &pubkey));
    
    // Create identical events
    nostr_event* event1;
    nostr_event* event2;
    
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event1));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event2));
    
    // Set public key before computing ID
    memcpy(event1->pubkey.data, pubkey.data, NOSTR_PUBKEY_SIZE);
    memcpy(event2->pubkey.data, pubkey.data, NOSTR_PUBKEY_SIZE);
    
    event1->kind = 1;
    event2->kind = 1;
    event1->created_at = 1234567890;
    event2->created_at = 1234567890;
    
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_set_content(event1, "Same content"));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_set_content(event2, "Same content"));
    
    // Compute IDs
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_compute_id(event1));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_compute_id(event2));
    
    // Event IDs should be identical for identical content
    TEST_ASSERT_EQUAL_MEMORY(event1->id, event2->id, NOSTR_ID_SIZE);
    
    nostr_event_destroy(event1);
    nostr_event_destroy(event2);
}

void run_key_tests(void)
{
    printf("Running key tests...\n");
    
    test_key_generation();
    printf("   Key generation\n");
    
    test_event_signing_and_verification();
    printf("   Event signing and verification\n");
    
    test_multiple_signatures();
    printf("   Multiple signatures\n");
    
    test_deterministic_event_ids();
    printf("   Deterministic event IDs\n");
}