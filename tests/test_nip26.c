#ifdef HAVE_UNITY
#include "unity.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/nostr.h"
#include "../include/nostr_features.h"

#ifdef NOSTR_FEATURE_NIP26

#ifndef HAVE_UNITY
static int g_test_failed = 0;
static int g_tests_failed_count = 0;

#define TEST_ASSERT_EQUAL(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("Assertion failed: %s != %s (expected %d, got %d)\n", \
                   #expected, #actual, (int)(expected), (int)(actual)); \
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

#define TEST_ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            printf("Condition failed: %s\n", #condition); \
            g_test_failed = 1; \
            return; \
        } \
    } while(0)

#define TEST_ASSERT_EQUAL_STRING(expected, actual) \
    do { \
        const char* _exp = (expected); \
        const char* _act = (actual); \
        if (_exp == NULL && _act == NULL) break; \
        if (_exp == NULL || _act == NULL || strcmp(_exp, _act) != 0) { \
            printf("String comparison failed: '%s' != '%s'\n", \
                   _exp ? _exp : "NULL", _act ? _act : "NULL"); \
            g_test_failed = 1; \
            return; \
        } \
    } while(0)

#define RUN_TEST(test_func, test_name) \
    do { \
        g_test_failed = 0; \
        test_func(); \
        if (g_test_failed) { \
            printf("     FAILED: %s\n", test_name); \
            g_tests_failed_count++; \
        } else { \
            printf("     Success: %s\n", test_name); \
        } \
    } while(0)
#endif

static void test_delegation_create_and_verify(void)
{
    nostr_init();

    nostr_keypair delegator, delegatee;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegator));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegatee));

    const char *conditions = "kind=1&created_at>1000000000&created_at<2000000000";
    nostr_delegation delegation;

    nostr_error_t err = nostr_delegation_create(
        &delegator.privkey,
        &delegatee.pubkey,
        conditions,
        &delegation
    );
    TEST_ASSERT_EQUAL(NOSTR_OK, err);
    TEST_ASSERT_EQUAL_STRING(conditions, delegation.conditions);
    TEST_ASSERT_TRUE(memcmp(delegation.delegator_pubkey.data, delegator.pubkey.data, 32) == 0);

    err = nostr_delegation_verify(&delegation, &delegatee.pubkey);
    TEST_ASSERT_EQUAL(NOSTR_OK, err);

    nostr_delegation_free(&delegation);
    nostr_keypair_destroy(&delegator);
    nostr_keypair_destroy(&delegatee);
}

static void test_delegation_verify_wrong_delegatee(void)
{
    nostr_init();

    nostr_keypair delegator, delegatee, wrong_delegatee;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegator));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegatee));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&wrong_delegatee));

    const char *conditions = "kind=1";
    nostr_delegation delegation;

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_delegation_create(
        &delegator.privkey, &delegatee.pubkey, conditions, &delegation));

    nostr_error_t err = nostr_delegation_verify(&delegation, &wrong_delegatee.pubkey);
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_SIGNATURE, err);

    nostr_delegation_free(&delegation);
    nostr_keypair_destroy(&delegator);
    nostr_keypair_destroy(&delegatee);
    nostr_keypair_destroy(&wrong_delegatee);
}

static void test_delegation_check_conditions_kind(void)
{
    nostr_init();

    nostr_keypair delegator, delegatee;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegator));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegatee));

    const char *conditions = "kind=1&kind=7";
    nostr_delegation delegation;

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_delegation_create(
        &delegator.privkey, &delegatee.pubkey, conditions, &delegation));

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_delegation_check_conditions(&delegation, 1, time(NULL)));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_delegation_check_conditions(&delegation, 7, time(NULL)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, nostr_delegation_check_conditions(&delegation, 0, time(NULL)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, nostr_delegation_check_conditions(&delegation, 30023, time(NULL)));

    nostr_delegation_free(&delegation);
    nostr_keypair_destroy(&delegator);
    nostr_keypair_destroy(&delegatee);
}

static void test_delegation_check_conditions_created_at(void)
{
    nostr_init();

    nostr_keypair delegator, delegatee;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegator));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegatee));

    const char *conditions = "created_at>1000000000&created_at<2000000000";
    nostr_delegation delegation;

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_delegation_create(
        &delegator.privkey, &delegatee.pubkey, conditions, &delegation));

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_delegation_check_conditions(&delegation, 1, 1500000000));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, nostr_delegation_check_conditions(&delegation, 1, 900000000));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, nostr_delegation_check_conditions(&delegation, 1, 2100000000));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, nostr_delegation_check_conditions(&delegation, 1, 1000000000));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, nostr_delegation_check_conditions(&delegation, 1, 2000000000));

    nostr_delegation_free(&delegation);
    nostr_keypair_destroy(&delegator);
    nostr_keypair_destroy(&delegatee);
}

static void test_event_add_delegation(void)
{
    nostr_init();

    nostr_keypair delegator, delegatee;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegator));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegatee));

    const char *conditions = "kind=1";
    nostr_delegation delegation;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_delegation_create(
        &delegator.privkey, &delegatee.pubkey, conditions, &delegation));

    nostr_event *event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_set_content(event, "Hello from delegatee!"));

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_add_delegation(event, &delegation));

    int found_delegation = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 4 &&
            strcmp(event->tags[i].values[0], "delegation") == 0) {
            found_delegation = 1;
            TEST_ASSERT_EQUAL_STRING(conditions, event->tags[i].values[2]);
            TEST_ASSERT_TRUE(strlen(event->tags[i].values[1]) == 64);
            TEST_ASSERT_TRUE(strlen(event->tags[i].values[3]) == 128);
        }
    }
    TEST_ASSERT_TRUE(found_delegation);

    nostr_event_destroy(event);
    nostr_delegation_free(&delegation);
    nostr_keypair_destroy(&delegator);
    nostr_keypair_destroy(&delegatee);
}

static void test_event_get_delegation(void)
{
    nostr_init();

    nostr_keypair delegator, delegatee;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegator));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegatee));

    const char *conditions = "kind=1&created_at>1000";
    nostr_delegation delegation;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_delegation_create(
        &delegator.privkey, &delegatee.pubkey, conditions, &delegation));

    nostr_event *event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_add_delegation(event, &delegation));

    nostr_delegation retrieved;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_get_delegation(event, &retrieved));
    TEST_ASSERT_EQUAL_STRING(conditions, retrieved.conditions);
    TEST_ASSERT_TRUE(memcmp(retrieved.delegator_pubkey.data, delegator.pubkey.data, 32) == 0);
    TEST_ASSERT_TRUE(memcmp(retrieved.token, delegation.token, 64) == 0);

    nostr_delegation_free(&retrieved);
    nostr_event_destroy(event);
    nostr_delegation_free(&delegation);
    nostr_keypair_destroy(&delegator);
    nostr_keypair_destroy(&delegatee);
}

static void test_event_verify_delegation(void)
{
    nostr_init();

    nostr_keypair delegator, delegatee;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegator));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegatee));

    int64_t now = time(NULL);
    char conditions[128];
    snprintf(conditions, sizeof(conditions), "kind=1&created_at>%lld&created_at<%lld",
             (long long)(now - 3600), (long long)(now + 3600));

    nostr_delegation delegation;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_delegation_create(
        &delegator.privkey, &delegatee.pubkey, conditions, &delegation));

    nostr_event *event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;
    event->created_at = now;
    memcpy(event->pubkey.data, delegatee.pubkey.data, 32);
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_set_content(event, "Delegated message"));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_add_delegation(event, &delegation));

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_verify_delegation(event));

    nostr_event_destroy(event);
    nostr_delegation_free(&delegation);
    nostr_keypair_destroy(&delegator);
    nostr_keypair_destroy(&delegatee);
}

static void test_event_verify_delegation_wrong_kind(void)
{
    nostr_init();

    nostr_keypair delegator, delegatee;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegator));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&delegatee));

    const char *conditions = "kind=1";
    nostr_delegation delegation;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_delegation_create(
        &delegator.privkey, &delegatee.pubkey, conditions, &delegation));

    nostr_event *event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 7;
    memcpy(event->pubkey.data, delegatee.pubkey.data, 32);
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_add_delegation(event, &delegation));

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, nostr_event_verify_delegation(event));

    nostr_event_destroy(event);
    nostr_delegation_free(&delegation);
    nostr_keypair_destroy(&delegator);
    nostr_keypair_destroy(&delegatee);
}

static void test_event_no_delegation(void)
{
    nostr_init();

    nostr_event *event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;

    nostr_delegation delegation;
    TEST_ASSERT_EQUAL(NOSTR_ERR_NOT_FOUND, nostr_event_get_delegation(event, &delegation));
    TEST_ASSERT_EQUAL(NOSTR_ERR_NOT_FOUND, nostr_event_verify_delegation(event));

    nostr_event_destroy(event);
}

static void test_invalid_params(void)
{
    nostr_init();

    nostr_keypair kp;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_generate(&kp));

    nostr_delegation delegation;

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM,
        nostr_delegation_create(NULL, &kp.pubkey, "kind=1", &delegation));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM,
        nostr_delegation_create(&kp.privkey, NULL, "kind=1", &delegation));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM,
        nostr_delegation_create(&kp.privkey, &kp.pubkey, NULL, &delegation));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM,
        nostr_delegation_create(&kp.privkey, &kp.pubkey, "kind=1", NULL));

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_delegation_verify(NULL, &kp.pubkey));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_delegation_check_conditions(NULL, 1, 0));

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_add_delegation(NULL, &delegation));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_get_delegation(NULL, &delegation));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_verify_delegation(NULL));

    nostr_keypair_destroy(&kp);
}

static void test_nip26_spec_example(void)
{
    nostr_init();

    nostr_keypair delegator, delegatee;

    const char *delegator_privkey_hex = "ee35e8bb71131c02c1d7e73231daa48e9953d329a4b701f7133c8f46dd21139c";
    const char *delegatee_privkey_hex = "777e4f60b4aa87937e13acc84f7abcc3c93cc035cb4c1e9f7a9086dd78fffce1";

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_from_private_hex(&delegator, delegator_privkey_hex));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_keypair_from_private_hex(&delegatee, delegatee_privkey_hex));

    char delegator_pubkey_hex[65], delegatee_pubkey_hex[65];
    nostr_hex_encode(delegator.pubkey.data, 32, delegator_pubkey_hex);
    nostr_hex_encode(delegatee.pubkey.data, 32, delegatee_pubkey_hex);

    TEST_ASSERT_EQUAL_STRING("8e0d3d3eb2881ec137a11debe736a9086715a8c8beeeda615780064d68bc25dd", delegator_pubkey_hex);
    TEST_ASSERT_EQUAL_STRING("477318cfb5427b9cfc66a9fa376150c1ddbc62115ae27cef72417eb959691396", delegatee_pubkey_hex);

    const char *conditions = "kind=1&created_at>1674834236&created_at<1677426236";
    nostr_delegation delegation;

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_delegation_create(
        &delegator.privkey, &delegatee.pubkey, conditions, &delegation));

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_delegation_verify(&delegation, &delegatee.pubkey));

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_delegation_check_conditions(&delegation, 1, 1675000000));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, nostr_delegation_check_conditions(&delegation, 7, 1675000000));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, nostr_delegation_check_conditions(&delegation, 1, 1674000000));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_EVENT, nostr_delegation_check_conditions(&delegation, 1, 1680000000));

    nostr_delegation_free(&delegation);
    nostr_keypair_destroy(&delegator);
    nostr_keypair_destroy(&delegatee);
}

int run_nip26_tests(void)
{
#ifndef HAVE_UNITY
    g_tests_failed_count = 0;
#endif

    printf("   Running NIP-26 tests...\n");

#ifdef HAVE_UNITY
    RUN_TEST(test_delegation_create_and_verify);
    RUN_TEST(test_delegation_verify_wrong_delegatee);
    RUN_TEST(test_delegation_check_conditions_kind);
    RUN_TEST(test_delegation_check_conditions_created_at);
    RUN_TEST(test_event_add_delegation);
    RUN_TEST(test_event_get_delegation);
    RUN_TEST(test_event_verify_delegation);
    RUN_TEST(test_event_verify_delegation_wrong_kind);
    RUN_TEST(test_event_no_delegation);
    RUN_TEST(test_invalid_params);
    RUN_TEST(test_nip26_spec_example);
#else
    RUN_TEST(test_delegation_create_and_verify, "test_delegation_create_and_verify");
    RUN_TEST(test_delegation_verify_wrong_delegatee, "test_delegation_verify_wrong_delegatee");
    RUN_TEST(test_delegation_check_conditions_kind, "test_delegation_check_conditions_kind");
    RUN_TEST(test_delegation_check_conditions_created_at, "test_delegation_check_conditions_created_at");
    RUN_TEST(test_event_add_delegation, "test_event_add_delegation");
    RUN_TEST(test_event_get_delegation, "test_event_get_delegation");
    RUN_TEST(test_event_verify_delegation, "test_event_verify_delegation");
    RUN_TEST(test_event_verify_delegation_wrong_kind, "test_event_verify_delegation_wrong_kind");
    RUN_TEST(test_event_no_delegation, "test_event_no_delegation");
    RUN_TEST(test_invalid_params, "test_invalid_params");
    RUN_TEST(test_nip26_spec_example, "test_nip26_spec_example");
#endif

#ifndef HAVE_UNITY
    if (g_tests_failed_count > 0) {
        printf("   FAILED: %d NIP-26 test(s) failed!\n", g_tests_failed_count);
        return g_tests_failed_count;
    }
#endif
    printf("   All NIP-26 tests passed!\n");
    return 0;
}

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    printf("Running NIP-26 tests...\n\n");
    int result = run_nip26_tests();
    return result;
}
#endif

#else

int run_nip26_tests(void)
{
    printf("   NIP-26 tests skipped (NIP-26 not enabled)\n");
    return 0;
}

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    printf("NIP-26 not enabled in build\n");
    return 0;
}
#endif

#endif
