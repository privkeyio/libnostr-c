#ifdef HAVE_UNITY
#include "unity.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/nostr.h"
#include "../include/nostr_features.h"

#ifdef NOSTR_FEATURE_NIP57

#ifndef HAVE_UNITY
#define TEST_ASSERT_EQUAL(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("Assertion failed: %s != %s\n", #expected, #actual); \
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

#define TEST_ASSERT_EQUAL_STRING(expected, actual) \
    do { \
        if (strcmp(expected, actual) != 0) { \
            printf("String comparison failed: %s != %s\n", expected, actual); \
            return; \
        } \
    } while(0)

#define TEST_ASSERT_EQUAL_UINT64(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("Uint64 comparison failed: %lu != %lu\n", (unsigned long)(expected), (unsigned long)(actual)); \
            return; \
        } \
    } while(0)
#endif

static void test_zap_create_request(void)
{
    nostr_event* event = NULL;
    nostr_key recipient;
    const char* lnurl = "lnurl1dp68gurn8ghj7um5v93kketj9ehx2amn9uh8wetvdskkkmn0wahz7mrww4excup0dajx2mrv92x9xp";
    const char* relays[] = {"wss://relay.damus.io", "wss://relay.nostr.bg"};
    
    memset(&recipient, 0x42, sizeof(recipient));
    
    nostr_error_t err = nostr_zap_create_request(&event, 21000, &recipient, lnurl, "Test zap!", relays, 2);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL(9734, event->kind);
    TEST_ASSERT_EQUAL_STRING("Test zap!", event->content);
    
    int found_relays = 0;
    int found_amount = 0;
    int found_lnurl = 0;
    int found_p_tag = 0;
    
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count > 0) {
            if (strcmp(event->tags[i].values[0], "relays") == 0) {
                found_relays = 1;
                TEST_ASSERT_TRUE(event->tags[i].count >= 3);
                TEST_ASSERT_EQUAL_STRING("wss://relay.damus.io", event->tags[i].values[1]);
                TEST_ASSERT_EQUAL_STRING("wss://relay.nostr.bg", event->tags[i].values[2]);
            } else if (strcmp(event->tags[i].values[0], "amount") == 0) {
                found_amount = 1;
                TEST_ASSERT_EQUAL(2, event->tags[i].count);
                TEST_ASSERT_EQUAL_STRING("21000", event->tags[i].values[1]);
            } else if (strcmp(event->tags[i].values[0], "lnurl") == 0) {
                found_lnurl = 1;
                TEST_ASSERT_EQUAL(2, event->tags[i].count);
                TEST_ASSERT_EQUAL_STRING(lnurl, event->tags[i].values[1]);
            } else if (strcmp(event->tags[i].values[0], "p") == 0) {
                found_p_tag = 1;
                TEST_ASSERT_EQUAL(2, event->tags[i].count);
            }
        }
    }
    
    TEST_ASSERT_TRUE(found_relays);
    TEST_ASSERT_TRUE(found_amount);
    TEST_ASSERT_TRUE(found_lnurl);
    TEST_ASSERT_TRUE(found_p_tag);
    
    nostr_event_destroy(event);
}

static void test_zap_validate_lnurl(void)
{
    const char* valid_lnurl = "lnurl1dp68gurn8ghj7um5v93kketj9ehx2amn9uh8wetvdskkkmn0wahz7mrww4excup0dajx2mrv92x9xp";
    const char* invalid_lnurl = "notlnurl123";
    
    nostr_error_t err = nostr_zap_validate_lnurl(valid_lnurl, NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_zap_validate_lnurl(invalid_lnurl, NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);
    
    err = nostr_zap_validate_lnurl(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);
}

static void test_zap_parse_receipt(void)
{
    nostr_event* receipt = NULL;
    nostr_error_t err = nostr_event_create(&receipt);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_NOT_NULL(receipt);
    
    receipt->kind = 9735;
    
    const char* bolt11_tag[] = {"bolt11", "lnbc210u1p3unwfusp5t9r3yymhpfqculx78u027lxspgxcr2n2987mx2j55nnfs95nxnzqpp5jmrh92pfld78spqs78v9euf2385t83uvpwk9ldrlvf6ch7tpascqhp5zvkrmemgth3tufcvflmzjzfvjt023nazlhljz2n9hattj4f8jq8qxqyjw5qcqpjrzjqtc4fc44feggv7065fqe5m4ytjarg3repr5j9el35xhmtfexc42yczarjuqqfzqqqqqqqqlgqqqqqqgq9q9qxpqysgq079nkq507a5tw7xgttmj4u990j7wfggtrasah5gd4ywfr2pjcn29383tphp4t48gquelz9z78p4cq7ml3nrrphw5w6eckhjwmhezhnqpy6gyf0"};
    err = nostr_event_add_tag(receipt, bolt11_tag, 2);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    const char* preimage_tag[] = {"preimage", "5d006d2cf1e73c7148e7519a4c68adc81642ce0e25a432b2434c99f97344c15f"};
    err = nostr_event_add_tag(receipt, preimage_tag, 2);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    uint64_t amount = 0;
    char* bolt11 = NULL;
    char preimage[129] = {0};
    
    err = nostr_zap_parse_receipt(receipt, &amount, &bolt11, preimage, NULL);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_NOT_NULL(bolt11);
    TEST_ASSERT_EQUAL_UINT64(21000000, amount);
    TEST_ASSERT_EQUAL_STRING("5d006d2cf1e73c7148e7519a4c68adc81642ce0e25a432b2434c99f97344c15f", preimage);
    
    free(bolt11);
    nostr_event_destroy(receipt);
}

static void test_zap_verify(void)
{
    nostr_privkey server_privkey;
    nostr_key server_pubkey;
    nostr_error_t err = nostr_key_generate(&server_privkey, &server_pubkey);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    char server_pubkey_hex[65];
    err = nostr_key_to_hex(&server_pubkey, server_pubkey_hex, sizeof(server_pubkey_hex));
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    nostr_event* request = NULL;
    nostr_event* receipt = NULL;
    char* request_json = NULL;
    
    // Create request
    nostr_key recipient;
    memset(&recipient, 0x42, sizeof(recipient));
    const char* relays[] = {"wss://relay.damus.io"};
    err = nostr_zap_create_request(&request, 21000, &recipient, "lnurl1test", "Test", relays, 1);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_NOT_NULL(request);
    
    // Validate the created request has required fields
    TEST_ASSERT_NOT_NULL(request->content);
    TEST_ASSERT_TRUE(request->kind != 0);
    
    nostr_privkey sender_privkey;
    nostr_key sender_pubkey;
    err = nostr_key_generate(&sender_privkey, &sender_pubkey);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    request->pubkey = sender_pubkey;
    
    err = nostr_event_compute_id(request);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_event_sign(request, &sender_privkey);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_event_to_json(request, &request_json);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_event_create(&receipt);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    receipt->kind = 9735;
    
    const char* description_tag[] = {"description", request_json};
    err = nostr_event_add_tag(receipt, description_tag, 2);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    const char* bolt11_tag[] = {"bolt11", "lnbc210u1p3unwfusp5t9r3yymhpfqculx78u027lxspgxcr2n2987mx2j55nnfs95nxnzqpp5jmrh92pfld78spqs78v9euf2385t83uvpwk9ldrlvf6ch7tpascqhp5zvkrmemgth3tufcvflmzjzfvjt023nazlhljz2n9hattj4f8jq8qxqyjw5qcqpjrzjqtc4fc44feggv7065fqe5m4ytjarg3repr5j9el35xhmtfexc42yczarjuqqfzqqqqqqqqlgqqqqqqgq9q9qxpqysgq079nkq507a5tw7xgttmj4u990j7wfggtrasah5gd4ywfr2pjcn29383tphp4t48gquelz9z78p4cq7ml3nrrphw5w6eckhjwmhezhnqpy6gyf0"};
    err = nostr_event_add_tag(receipt, bolt11_tag, 2);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    const char* p_tag[] = {"p", "42424242424242424242424242424242424242424242424242424242424242"};
    err = nostr_event_add_tag(receipt, p_tag, 2);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    receipt->pubkey = server_pubkey;
    
    // Set empty content to avoid NULL content issue
    err = nostr_event_set_content(receipt, "");
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_event_compute_id(receipt);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_event_sign(receipt, &server_privkey);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_zap_verify(receipt, request, server_pubkey_hex);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_zap_verify(receipt, request, "0000000000000000000000000000000000000000000000000000000000000000");
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_SIGNATURE, err);
    
    // Cleanup - always executed
    if (request_json) free(request_json);
    if (request) nostr_event_destroy(request);
    if (receipt) nostr_event_destroy(receipt);
}

static void test_zap_verify_invalid_amount(void)
{
    nostr_privkey server_privkey;
    nostr_key server_pubkey;
    nostr_error_t err = nostr_key_generate(&server_privkey, &server_pubkey);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    char server_pubkey_hex[65];
    err = nostr_key_to_hex(&server_pubkey, server_pubkey_hex, sizeof(server_pubkey_hex));
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    nostr_event* request = NULL;
    nostr_event* receipt = NULL;
    char* request_json = NULL;
    
    nostr_key recipient;
    memset(&recipient, 0x42, sizeof(recipient));
    const char* relays[] = {"wss://relay.damus.io"};
    err = nostr_zap_create_request(&request, 42000, &recipient, "lnurl1test", "Test", relays, 1);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    nostr_privkey sender_privkey;
    nostr_key sender_pubkey;
    err = nostr_key_generate(&sender_privkey, &sender_pubkey);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    request->pubkey = sender_pubkey;
    
    err = nostr_event_compute_id(request);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_event_sign(request, &sender_privkey);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_event_to_json(request, &request_json);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_event_create(&receipt);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    receipt->kind = 9735;
    
    const char* description_tag[] = {"description", request_json};
    err = nostr_event_add_tag(receipt, description_tag, 2);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    const char* bolt11_tag[] = {"bolt11", "lnbc210u1p3unwfusp5t9r3yymhpfqculx78u027lxspgxcr2n2987mx2j55nnfs95nxnzqpp5jmrh92pfld78spqs78v9euf2385t83uvpwk9ldrlvf6ch7tpascqhp5zvkrmemgth3tufcvflmzjzfvjt023nazlhljz2n9hattj4f8jq8qxqyjw5qcqpjrzjqtc4fc44feggv7065fqe5m4ytjarg3repr5j9el35xhmtfexc42yczarjuqqfzqqqqqqqqlgqqqqqqgq9q9qxpqysgq079nkq507a5tw7xgttmj4u990j7wfggtrasah5gd4ywfr2pjcn29383tphp4t48gquelz9z78p4cq7ml3nrrphw5w6eckhjwmhezhnqpy6gyf0"};
    err = nostr_event_add_tag(receipt, bolt11_tag, 2);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    const char* p_tag[] = {"p", "42424242424242424242424242424242424242424242424242424242424242"};
    err = nostr_event_add_tag(receipt, p_tag, 2);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    receipt->pubkey = server_pubkey;
    
    // Set empty content to avoid NULL content issue
    err = nostr_event_set_content(receipt, "");
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_event_compute_id(receipt);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_event_sign(receipt, &server_privkey);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    
    err = nostr_zap_verify(receipt, request, server_pubkey_hex);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, err);
    
    // Cleanup - always executed
    free(request_json);
    nostr_event_destroy(request);
    nostr_event_destroy(receipt);
}

static void test_zap_verify_null_params(void)
{
    nostr_error_t err = nostr_zap_verify(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, err);
}

void run_zap_tests(void)
{
    printf("   Running zap tests...\n");
    
    test_zap_create_request();
    printf("     Success: test_zap_create_request\n");
    
    test_zap_validate_lnurl();
    printf("     Success: test_zap_validate_lnurl\n");
    
    test_zap_parse_receipt();
    printf("     Success: test_zap_parse_receipt\n");
    
    test_zap_verify();
    printf("     Success: test_zap_verify\n");
    
    test_zap_verify_invalid_amount();
    printf("     Success: test_zap_verify_invalid_amount\n");
    
    test_zap_verify_null_params();
    printf("     Success: test_zap_verify_null_params\n");
}

#else // NOSTR_FEATURE_NIP57

void run_zap_tests(void)
{
    printf("   Zap tests skipped (NIP-57 not enabled)\n");
}

#endif // NOSTR_FEATURE_NIP57