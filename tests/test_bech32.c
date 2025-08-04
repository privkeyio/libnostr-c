#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../include/nostr.h"
#include "unity.h"

static void test_npub_encoding_decoding(void) {
    nostr_key key;
    const char* hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const char* expected_npub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_from_hex(hex, &key));
    
    char bech32[100];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_to_bech32(&key, "npub", bech32, sizeof(bech32)));
    TEST_ASSERT_EQUAL_STRING(expected_npub, bech32);
    
    nostr_key decoded_key;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_from_bech32(bech32, &decoded_key));
    TEST_ASSERT_EQUAL_MEMORY(key.data, decoded_key.data, NOSTR_PUBKEY_SIZE);
}

static void test_nsec_encoding_decoding(void) {
    nostr_privkey privkey;
    const char* hex = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
    const char* expected_nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_privkey_from_hex(hex, &privkey));
    
    char bech32[100];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_privkey_to_bech32(&privkey, bech32, sizeof(bech32)));
    TEST_ASSERT_EQUAL_STRING(expected_nsec, bech32);
    
    nostr_privkey decoded_privkey;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_privkey_from_bech32(bech32, &decoded_privkey));
    TEST_ASSERT_EQUAL_MEMORY(privkey.data, decoded_privkey.data, NOSTR_PRIVKEY_SIZE);
}

static void test_note_encoding_decoding(void) {
    uint8_t id[NOSTR_ID_SIZE];
    const char* hex = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
    
    for (int i = 0; i < NOSTR_ID_SIZE; i++) {
        sscanf(hex + i * 2, "%2hhx", &id[i]);
    }
    
    char bech32[100];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_id_to_bech32(id, bech32, sizeof(bech32)));
    
    uint8_t decoded_id[NOSTR_ID_SIZE];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_id_from_bech32(bech32, decoded_id));
    TEST_ASSERT_EQUAL_MEMORY(id, decoded_id, NOSTR_ID_SIZE);
}

static void test_invalid_bech32_format(void) {
    nostr_key key;
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, nostr_key_from_bech32("invalid", &key));
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, nostr_key_from_bech32("npub1invalid", &key));
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, nostr_key_from_bech32("", &key));
    
    nostr_privkey privkey;
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, nostr_privkey_from_bech32("invalid", &privkey));
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, nostr_privkey_from_bech32("nsec1invalid", &privkey));
    
    uint8_t id[NOSTR_ID_SIZE];
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, nostr_event_id_from_bech32("invalid", id));
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, nostr_event_id_from_bech32("note1invalid", id));
}

static void test_null_parameters(void) {
    char bech32[100];
    nostr_key key;
    nostr_privkey privkey;
    uint8_t id[NOSTR_ID_SIZE];
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_key_to_bech32(NULL, "npub", bech32, sizeof(bech32)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_key_to_bech32(&key, NULL, bech32, sizeof(bech32)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_key_to_bech32(&key, "npub", NULL, sizeof(bech32)));
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_key_from_bech32(NULL, &key));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_key_from_bech32("npub123", NULL));
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_privkey_to_bech32(NULL, bech32, sizeof(bech32)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_privkey_to_bech32(&privkey, NULL, sizeof(bech32)));
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_privkey_from_bech32(NULL, &privkey));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_privkey_from_bech32("nsec123", NULL));
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_id_to_bech32(NULL, bech32, sizeof(bech32)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_id_to_bech32(id, NULL, sizeof(bech32)));
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_id_from_bech32(NULL, id));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_id_from_bech32("note123", NULL));
}

static void test_buffer_size_checks(void) {
    nostr_key key;
    nostr_privkey privkey;
    uint8_t id[NOSTR_ID_SIZE];
    char small_buffer[10];
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_key_to_bech32(&key, "npub", small_buffer, sizeof(small_buffer)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_privkey_to_bech32(&privkey, small_buffer, sizeof(small_buffer)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_id_to_bech32(id, small_buffer, sizeof(small_buffer)));
}

void run_bech32_tests(void) {
    printf("   Running Bech32 encoding/decoding tests...\n");
    
    RUN_TEST(test_npub_encoding_decoding);
    RUN_TEST(test_nsec_encoding_decoding);
    RUN_TEST(test_note_encoding_decoding);
    RUN_TEST(test_invalid_bech32_format);
    RUN_TEST(test_null_parameters);
    RUN_TEST(test_buffer_size_checks);
    
    printf("   Bech32 tests completed\n");
}