#ifdef HAVE_UNITY
#include "unity.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
        if (_exp == NULL && _act == NULL) { \
            break; \
        } \
        if (_exp == NULL) { \
            printf("String comparison failed: expected is NULL, actual='%s'\n", _act); \
            g_test_failed = 1; \
            return; \
        } \
        if (_act == NULL) { \
            printf("String comparison failed: expected='%s', actual is NULL\n", _exp); \
            g_test_failed = 1; \
            return; \
        } \
        if (strcmp(_exp, _act) != 0) { \
            printf("String comparison failed: '%s' != '%s'\n", _exp, _act); \
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

static void test_filter_clone_empty(void)
{
    nostr_filter_t src;
    nostr_filter_t dst;
    memset(&src, 0, sizeof(src));

    nostr_relay_error_t err = nostr_filter_clone(&dst, &src);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(0, dst.ids_count);
    TEST_ASSERT_EQUAL(0, dst.authors_count);
    TEST_ASSERT_EQUAL(0, dst.kinds_count);
    TEST_ASSERT_EQUAL(0, dst.e_tags_count);
    TEST_ASSERT_EQUAL(0, dst.p_tags_count);
    TEST_ASSERT_EQUAL(0, dst.generic_tags_count);
    TEST_ASSERT_EQUAL(0, dst.since);
    TEST_ASSERT_EQUAL(0, dst.until);
    TEST_ASSERT_EQUAL(0, dst.limit);

    nostr_filter_free(&dst);
}

static void test_filter_clone_ids(void)
{
    nostr_filter_t src;
    nostr_filter_t dst;
    memset(&src, 0, sizeof(src));

    char* ids[] = {
        strdup("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        strdup("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
    };
    src.ids = ids;
    src.ids_count = 2;

    nostr_relay_error_t err = nostr_filter_clone(&dst, &src);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(2, dst.ids_count);
    TEST_ASSERT_NOT_NULL(dst.ids);
    TEST_ASSERT_EQUAL_STRING(ids[0], dst.ids[0]);
    TEST_ASSERT_EQUAL_STRING(ids[1], dst.ids[1]);
    TEST_ASSERT_TRUE(dst.ids[0] != ids[0]);
    TEST_ASSERT_TRUE(dst.ids[1] != ids[1]);

    nostr_filter_free(&dst);
    free(ids[0]);
    free(ids[1]);
}

static void test_filter_clone_kinds(void)
{
    nostr_filter_t src;
    nostr_filter_t dst;
    memset(&src, 0, sizeof(src));

    int32_t kinds[] = {0, 1, 3, 7};
    src.kinds = kinds;
    src.kinds_count = 4;

    nostr_relay_error_t err = nostr_filter_clone(&dst, &src);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(4, dst.kinds_count);
    TEST_ASSERT_NOT_NULL(dst.kinds);
    TEST_ASSERT_EQUAL(0, dst.kinds[0]);
    TEST_ASSERT_EQUAL(1, dst.kinds[1]);
    TEST_ASSERT_EQUAL(3, dst.kinds[2]);
    TEST_ASSERT_EQUAL(7, dst.kinds[3]);
    TEST_ASSERT_TRUE(dst.kinds != kinds);

    nostr_filter_free(&dst);
}

static void test_filter_clone_scalar_fields(void)
{
    nostr_filter_t src;
    nostr_filter_t dst;
    memset(&src, 0, sizeof(src));

    src.since = 1000000000;
    src.until = 2000000000;
    src.limit = 100;

    nostr_relay_error_t err = nostr_filter_clone(&dst, &src);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(1000000000, dst.since);
    TEST_ASSERT_EQUAL(2000000000, dst.until);
    TEST_ASSERT_EQUAL(100, dst.limit);

    nostr_filter_free(&dst);
}

static void test_filter_clone_e_tags(void)
{
    nostr_filter_t src;
    nostr_filter_t dst;
    memset(&src, 0, sizeof(src));

    char* e_tags[] = {strdup("event_id_1"), strdup("event_id_2")};
    src.e_tags = e_tags;
    src.e_tags_count = 2;

    nostr_relay_error_t err = nostr_filter_clone(&dst, &src);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(2, dst.e_tags_count);
    TEST_ASSERT_EQUAL_STRING("event_id_1", dst.e_tags[0]);
    TEST_ASSERT_EQUAL_STRING("event_id_2", dst.e_tags[1]);

    nostr_filter_free(&dst);
    free(e_tags[0]);
    free(e_tags[1]);
}

static void test_filter_clone_p_tags(void)
{
    nostr_filter_t src;
    nostr_filter_t dst;
    memset(&src, 0, sizeof(src));

    char* p_tags[] = {strdup("pubkey_1")};
    src.p_tags = p_tags;
    src.p_tags_count = 1;

    nostr_relay_error_t err = nostr_filter_clone(&dst, &src);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(1, dst.p_tags_count);
    TEST_ASSERT_EQUAL_STRING("pubkey_1", dst.p_tags[0]);

    nostr_filter_free(&dst);
    free(p_tags[0]);
}

static void test_filter_clone_generic_tags(void)
{
    nostr_filter_t src;
    nostr_filter_t dst;
    memset(&src, 0, sizeof(src));

    nostr_generic_tag_filter_t generic[2];
    char* t_values[] = {strdup("bitcoin"), strdup("nostr")};
    char* a_values[] = {strdup("30023:pk:id")};

    generic[0].tag_name = 't';
    generic[0].values = t_values;
    generic[0].values_count = 2;

    generic[1].tag_name = 'a';
    generic[1].values = a_values;
    generic[1].values_count = 1;

    src.generic_tags = generic;
    src.generic_tags_count = 2;

    nostr_relay_error_t err = nostr_filter_clone(&dst, &src);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(2, dst.generic_tags_count);
    TEST_ASSERT_NOT_NULL(dst.generic_tags);

    TEST_ASSERT_EQUAL('t', dst.generic_tags[0].tag_name);
    TEST_ASSERT_EQUAL(2, dst.generic_tags[0].values_count);
    TEST_ASSERT_EQUAL_STRING("bitcoin", dst.generic_tags[0].values[0]);
    TEST_ASSERT_EQUAL_STRING("nostr", dst.generic_tags[0].values[1]);

    TEST_ASSERT_EQUAL('a', dst.generic_tags[1].tag_name);
    TEST_ASSERT_EQUAL(1, dst.generic_tags[1].values_count);
    TEST_ASSERT_EQUAL_STRING("30023:pk:id", dst.generic_tags[1].values[0]);

    nostr_filter_free(&dst);
    free(t_values[0]);
    free(t_values[1]);
    free(a_values[0]);
}

static void test_filter_clone_full(void)
{
    nostr_filter_t src;
    nostr_filter_t dst;
    memset(&src, 0, sizeof(src));

    char* ids[] = {strdup("id1")};
    char* authors[] = {strdup("author1"), strdup("author2")};
    int32_t kinds[] = {1, 7};
    char* e_tags[] = {strdup("e1")};
    char* p_tags[] = {strdup("p1")};

    src.ids = ids;
    src.ids_count = 1;
    src.authors = authors;
    src.authors_count = 2;
    src.kinds = kinds;
    src.kinds_count = 2;
    src.e_tags = e_tags;
    src.e_tags_count = 1;
    src.p_tags = p_tags;
    src.p_tags_count = 1;
    src.since = 1000;
    src.until = 2000;
    src.limit = 50;

    nostr_relay_error_t err = nostr_filter_clone(&dst, &src);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);

    TEST_ASSERT_EQUAL(1, dst.ids_count);
    TEST_ASSERT_EQUAL(2, dst.authors_count);
    TEST_ASSERT_EQUAL(2, dst.kinds_count);
    TEST_ASSERT_EQUAL(1, dst.e_tags_count);
    TEST_ASSERT_EQUAL(1, dst.p_tags_count);
    TEST_ASSERT_EQUAL(1000, dst.since);
    TEST_ASSERT_EQUAL(2000, dst.until);
    TEST_ASSERT_EQUAL(50, dst.limit);

    nostr_filter_free(&dst);
    free(ids[0]);
    free(authors[0]);
    free(authors[1]);
    free(e_tags[0]);
    free(p_tags[0]);
}

static void test_filter_clone_null_params(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_JSON, nostr_filter_clone(NULL, &filter));
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_JSON, nostr_filter_clone(&filter, NULL));
    TEST_ASSERT_EQUAL(NOSTR_RELAY_ERR_INVALID_JSON, nostr_filter_clone(NULL, NULL));
}

static void test_filter_clone_independence(void)
{
    nostr_filter_t src;
    nostr_filter_t dst;
    memset(&src, 0, sizeof(src));

    char* ids[] = {strdup("original_id")};
    src.ids = ids;
    src.ids_count = 1;

    nostr_relay_error_t err = nostr_filter_clone(&dst, &src);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);

    free(ids[0]);
    ids[0] = strdup("modified_id");

    TEST_ASSERT_EQUAL_STRING("original_id", dst.ids[0]);

    nostr_filter_free(&dst);
    free(ids[0]);
}

int run_filter_clone_tests(void)
{
#ifndef HAVE_UNITY
    g_tests_failed_count = 0;
#endif

    printf("Running filter_clone tests...\n");

#ifdef HAVE_UNITY
    RUN_TEST(test_filter_clone_empty);
    RUN_TEST(test_filter_clone_ids);
    RUN_TEST(test_filter_clone_kinds);
    RUN_TEST(test_filter_clone_scalar_fields);
    RUN_TEST(test_filter_clone_e_tags);
    RUN_TEST(test_filter_clone_p_tags);
    RUN_TEST(test_filter_clone_generic_tags);
    RUN_TEST(test_filter_clone_full);
    RUN_TEST(test_filter_clone_null_params);
    RUN_TEST(test_filter_clone_independence);
#else
    RUN_TEST(test_filter_clone_empty, "filter_clone_empty");
    RUN_TEST(test_filter_clone_ids, "filter_clone_ids");
    RUN_TEST(test_filter_clone_kinds, "filter_clone_kinds");
    RUN_TEST(test_filter_clone_scalar_fields, "filter_clone_scalar_fields");
    RUN_TEST(test_filter_clone_e_tags, "filter_clone_e_tags");
    RUN_TEST(test_filter_clone_p_tags, "filter_clone_p_tags");
    RUN_TEST(test_filter_clone_generic_tags, "filter_clone_generic_tags");
    RUN_TEST(test_filter_clone_full, "filter_clone_full");
    RUN_TEST(test_filter_clone_null_params, "filter_clone_null_params");
    RUN_TEST(test_filter_clone_independence, "filter_clone_independence");
#endif

#ifndef HAVE_UNITY
    if (g_tests_failed_count > 0) {
        printf("FAILED: %d test(s) failed!\n", g_tests_failed_count);
        return g_tests_failed_count;
    }
#endif
    printf("All filter_clone tests passed!\n");
    return 0;
}

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    nostr_init();
    int result = run_filter_clone_tests();
    nostr_cleanup();
    return result;
}
#endif
