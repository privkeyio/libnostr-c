#include <stdio.h>
#include <nostr.h>
#include <nostr_features.h>
#include "unity.h"

// Event tests
void test_event_create_destroy(void);
void test_event_create_invalid_param(void);
void test_event_set_content(void);
void test_event_set_content_invalid_params(void);
void test_event_add_tag(void);
void test_event_add_tag_invalid_params(void);
void test_event_compute_id(void);
void test_event_to_json(void);
void test_event_from_json(void);
void test_event_from_json_invalid(void);

// Key tests
void run_key_tests(void);

// Other test functions
void run_event_tests(void);
void run_bech32_tests(void);
void run_nip05_tests(void);
void run_nip21_tests(void);
void run_relay_tests(void);
void run_zap_tests(void);
void run_nip10_tests(void);
int run_nip18_tests(void);
void run_nip25_tests(void);
void run_utils_tests(void);
void run_coverage_tests(void);

int main(void)
{
    printf("Running libnostr-c tests...\n\n");
    
    // Run event tests
    printf("Event tests:\n");
    run_event_tests();
    printf("\n");
    
    // Run key/crypto tests
    run_key_tests();
    printf("\n");
    
    // Run other tests
    printf("Bech32 tests:\n");
    run_bech32_tests();
    printf("\n");

#ifdef NOSTR_FEATURE_NIP05
    printf("NIP-05 tests:\n");
    run_nip05_tests();
    printf("\n");
#endif

    printf("NIP-21 tests:\n");
    run_nip21_tests();
    printf("\n");

#ifdef NOSTR_FEATURE_RELAY
    printf("Relay tests:\n");
    run_relay_tests();
    printf("\n");
#endif
    
#ifdef NOSTR_FEATURE_NIP57
    printf("Zap tests:\n");
    run_zap_tests();
    printf("\n");
#endif

#ifdef NOSTR_FEATURE_NIP10
    printf("NIP-10 tests:\n");
    run_nip10_tests();
    printf("\n");
#endif

#ifdef NOSTR_FEATURE_NIP18
    printf("NIP-18 tests:\n");
    run_nip18_tests();
    printf("\n");
#endif

#ifdef NOSTR_FEATURE_NIP25
    printf("NIP-25 tests:\n");
    run_nip25_tests();
    printf("\n");
#endif

    printf("Utils tests:\n");
    run_utils_tests();
    printf("\n");
    
    printf("Coverage tests:\n");
    run_coverage_tests();
    printf("\n");
    
    printf("All tests completed!\n");
    return 0;
}

void run_coverage_tests(void)
{
    const char* error_msg;
    
    UNITY_BEGIN();
    
    error_msg = nostr_error_string(NOSTR_OK);
    TEST_ASSERT_NOT_NULL(error_msg);
    
    error_msg = nostr_error_string(NOSTR_ERR_INVALID_PARAM);
    TEST_ASSERT_NOT_NULL(error_msg);
    
    error_msg = nostr_error_string(NOSTR_ERR_MEMORY);
    TEST_ASSERT_NOT_NULL(error_msg);
    
    printf("  Success: Error string functions\n");
    
    UNITY_END();
}

void run_utils_tests(void)
{
    extern void test_constant_time_memcmp_equal(void);
    extern void test_constant_time_memcmp_different(void);
    extern void test_constant_time_memcmp_zero_length(void);
    extern void test_constant_time_memcmp_single_bit_difference(void);
    extern void test_constant_time_memcmp_first_byte_difference(void);
    extern void test_constant_time_memcmp_last_byte_difference(void);
    
    UNITY_BEGIN();
    
    RUN_TEST(test_constant_time_memcmp_equal);
    RUN_TEST(test_constant_time_memcmp_different);
    RUN_TEST(test_constant_time_memcmp_zero_length);
    RUN_TEST(test_constant_time_memcmp_single_bit_difference);
    RUN_TEST(test_constant_time_memcmp_first_byte_difference);
    RUN_TEST(test_constant_time_memcmp_last_byte_difference);
    
    printf("  Success: Constant-time memory comparison functions\n");
    
    UNITY_END();
}