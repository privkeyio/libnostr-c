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

static bool search_cb_contains(const char* query, const nostr_event* event, void* user_data)
{
    (void)user_data;
    if (!query || !event || !event->content)
        return false;
    return strstr(event->content, query) != NULL;
}

static bool search_cb_always_false(const char* query, const nostr_event* event, void* user_data)
{
    (void)query;
    (void)event;
    (void)user_data;
    return false;
}

static void test_filter_parse_search(void)
{
    const char* json = "{\"search\":\"best nostr apps\",\"kinds\":[1]}";
    nostr_filter_t filter;
    nostr_relay_error_t err = nostr_filter_parse(json, strlen(json), &filter);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_NOT_NULL(filter.search);
    TEST_ASSERT_EQUAL_STRING("best nostr apps", filter.search);
    TEST_ASSERT_EQUAL(1, filter.kinds_count);
    TEST_ASSERT_EQUAL(1, filter.kinds[0]);

    nostr_filter_free(&filter);
}

static void test_filter_parse_no_search(void)
{
    const char* json = "{\"kinds\":[1]}";
    nostr_filter_t filter;
    nostr_relay_error_t err = nostr_filter_parse(json, strlen(json), &filter);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_NULL(filter.search);
    TEST_ASSERT_FALSE(nostr_filter_has_search(&filter));

    nostr_filter_free(&filter);
}

static void test_filter_parse_empty_search(void)
{
    const char* json = "{\"search\":\"\",\"kinds\":[1]}";
    nostr_filter_t filter;
    nostr_relay_error_t err = nostr_filter_parse(json, strlen(json), &filter);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_NOT_NULL(filter.search);
    TEST_ASSERT_EQUAL_STRING("", filter.search);
    TEST_ASSERT_FALSE(nostr_filter_has_search(&filter));

    nostr_filter_free(&filter);
}

static void test_filter_get_search(void)
{
    const char* json = "{\"search\":\"bitcoin lightning\"}";
    nostr_filter_t filter;
    nostr_filter_parse(json, strlen(json), &filter);

    const char* search = nostr_filter_get_search(&filter);
    TEST_ASSERT_NOT_NULL(search);
    TEST_ASSERT_EQUAL_STRING("bitcoin lightning", search);
    TEST_ASSERT_TRUE(nostr_filter_has_search(&filter));

    nostr_filter_free(&filter);
}

static void test_filter_get_search_null_filter(void)
{
    const char* search = nostr_filter_get_search(NULL);
    TEST_ASSERT_NULL(search);
    TEST_ASSERT_FALSE(nostr_filter_has_search(NULL));
}

static void test_filter_clone_with_search(void)
{
    nostr_filter_t src;
    nostr_filter_t dst;
    memset(&src, 0, sizeof(src));

    src.search = strdup("test query");
    int32_t kinds[] = {1};
    src.kinds = kinds;
    src.kinds_count = 1;

    nostr_relay_error_t err = nostr_filter_clone(&dst, &src);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_NOT_NULL(dst.search);
    TEST_ASSERT_EQUAL_STRING("test query", dst.search);
    TEST_ASSERT_TRUE(dst.search != src.search);

    nostr_filter_free(&dst);
    free(src.search);
}

static void test_filter_clone_no_search(void)
{
    nostr_filter_t src;
    nostr_filter_t dst;
    memset(&src, 0, sizeof(src));

    nostr_relay_error_t err = nostr_filter_clone(&dst, &src);
    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_NULL(dst.search);

    nostr_filter_free(&dst);
}

static void test_filter_matches_with_search_callback(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    filter.search = strdup("hello");

    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;
    nostr_event_set_content(event, "hello world");

    TEST_ASSERT_TRUE(nostr_filter_matches_with_search(&filter, event,
                                                       search_cb_contains, NULL));

    nostr_event_set_content(event, "goodbye world");
    TEST_ASSERT_FALSE(nostr_filter_matches_with_search(&filter, event,
                                                        search_cb_contains, NULL));

    nostr_event_destroy(event);
    free(filter.search);
}

static void test_filter_matches_with_search_no_callback(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    filter.search = strdup("test");

    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;
    nostr_event_set_content(event, "test content");

    TEST_ASSERT_FALSE(nostr_filter_matches_with_search(&filter, event, NULL, NULL));

    nostr_event_destroy(event);
    free(filter.search);
}

static void test_filter_matches_with_search_empty_search(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    filter.search = strdup("");

    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;

    TEST_ASSERT_TRUE(nostr_filter_matches_with_search(&filter, event, NULL, NULL));

    nostr_event_destroy(event);
    free(filter.search);
}

static void test_filter_matches_without_search(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    int32_t kinds[] = {1};
    filter.kinds = kinds;
    filter.kinds_count = 1;

    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;

    TEST_ASSERT_TRUE(nostr_filter_matches_with_search(&filter, event, NULL, NULL));
    TEST_ASSERT_TRUE(nostr_filter_matches_with_search(&filter, event,
                                                       search_cb_always_false, NULL));

    nostr_event_destroy(event);
}

static void test_filter_matches_search_with_kind_filter(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    int32_t kinds[] = {1};
    filter.kinds = kinds;
    filter.kinds_count = 1;
    filter.search = strdup("nostr");

    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;
    nostr_event_set_content(event, "I love nostr");

    TEST_ASSERT_TRUE(nostr_filter_matches_with_search(&filter, event,
                                                       search_cb_contains, NULL));

    event->kind = 7;
    TEST_ASSERT_FALSE(nostr_filter_matches_with_search(&filter, event,
                                                        search_cb_contains, NULL));

    nostr_event_destroy(event);
    free(filter.search);
}

static void test_filters_match_with_search(void)
{
    nostr_filter_t filters[2];
    memset(filters, 0, sizeof(filters));

    int32_t kinds1[] = {1};
    filters[0].kinds = kinds1;
    filters[0].kinds_count = 1;
    filters[0].search = strdup("bitcoin");

    int32_t kinds2[] = {7};
    filters[1].kinds = kinds2;
    filters[1].kinds_count = 1;

    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;
    nostr_event_set_content(event, "I love bitcoin");

    TEST_ASSERT_TRUE(nostr_filters_match_with_search(filters, 2, event,
                                                      search_cb_contains, NULL));

    nostr_event_set_content(event, "I love ethereum");
    TEST_ASSERT_FALSE(nostr_filters_match_with_search(filters, 2, event,
                                                       search_cb_contains, NULL));

    event->kind = 7;
    TEST_ASSERT_TRUE(nostr_filters_match_with_search(filters, 2, event,
                                                      search_cb_contains, NULL));

    nostr_event_destroy(event);
    free(filters[0].search);
}

static void test_filter_matches_basic_still_works(void)
{
    nostr_filter_t filter;
    memset(&filter, 0, sizeof(filter));

    filter.search = strdup("ignored search");
    int32_t kinds[] = {1};
    filter.kinds = kinds;
    filter.kinds_count = 1;

    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;

    TEST_ASSERT_TRUE(nostr_filter_matches(&filter, event));

    nostr_event_destroy(event);
    free(filter.search);
}

static void test_client_msg_parse_req_with_search(void)
{
    const char* json = "[\"REQ\",\"sub1\",{\"search\":\"best apps\",\"kinds\":[1]}]";
    nostr_client_msg_t msg;

    nostr_relay_error_t err = nostr_client_msg_parse(json, strlen(json), &msg);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(NOSTR_CLIENT_MSG_REQ, msg.type);
    TEST_ASSERT_EQUAL(1, msg.data.req.filters_count);
    TEST_ASSERT_NOT_NULL(msg.data.req.filters[0].search);
    TEST_ASSERT_EQUAL_STRING("best apps", msg.data.req.filters[0].search);
    TEST_ASSERT_EQUAL(1, msg.data.req.filters[0].kinds_count);

    nostr_client_msg_free(&msg);
}

static void test_client_msg_parse_multiple_filters_with_search(void)
{
    const char* json = "[\"REQ\",\"sub1\",{\"search\":\"orange\"},{\"kinds\":[1,2],\"search\":\"purple\"}]";
    nostr_client_msg_t msg;

    nostr_relay_error_t err = nostr_client_msg_parse(json, strlen(json), &msg);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_EQUAL(2, msg.data.req.filters_count);
    TEST_ASSERT_EQUAL_STRING("orange", msg.data.req.filters[0].search);
    TEST_ASSERT_EQUAL_STRING("purple", msg.data.req.filters[1].search);
    TEST_ASSERT_EQUAL(2, msg.data.req.filters[1].kinds_count);

    nostr_client_msg_free(&msg);
}

static void test_search_with_extensions(void)
{
    const char* json = "{\"search\":\"best nostr apps language:en include:spam\"}";
    nostr_filter_t filter;
    nostr_relay_error_t err = nostr_filter_parse(json, strlen(json), &filter);

    TEST_ASSERT_EQUAL(NOSTR_RELAY_OK, err);
    TEST_ASSERT_NOT_NULL(filter.search);
    TEST_ASSERT_EQUAL_STRING("best nostr apps language:en include:spam", filter.search);

    nostr_filter_free(&filter);
}

int run_nip50_tests(void)
{
#ifndef HAVE_UNITY
    g_tests_failed_count = 0;
#endif

    printf("Running NIP-50 search capability tests...\n");

#ifdef HAVE_UNITY
    RUN_TEST(test_filter_parse_search);
    RUN_TEST(test_filter_parse_no_search);
    RUN_TEST(test_filter_parse_empty_search);
    RUN_TEST(test_filter_get_search);
    RUN_TEST(test_filter_get_search_null_filter);
    RUN_TEST(test_filter_clone_with_search);
    RUN_TEST(test_filter_clone_no_search);
    RUN_TEST(test_filter_matches_with_search_callback);
    RUN_TEST(test_filter_matches_with_search_no_callback);
    RUN_TEST(test_filter_matches_with_search_empty_search);
    RUN_TEST(test_filter_matches_without_search);
    RUN_TEST(test_filter_matches_search_with_kind_filter);
    RUN_TEST(test_filters_match_with_search);
    RUN_TEST(test_filter_matches_basic_still_works);
    RUN_TEST(test_client_msg_parse_req_with_search);
    RUN_TEST(test_client_msg_parse_multiple_filters_with_search);
    RUN_TEST(test_search_with_extensions);
#else
    RUN_TEST(test_filter_parse_search, "filter_parse_search");
    RUN_TEST(test_filter_parse_no_search, "filter_parse_no_search");
    RUN_TEST(test_filter_parse_empty_search, "filter_parse_empty_search");
    RUN_TEST(test_filter_get_search, "filter_get_search");
    RUN_TEST(test_filter_get_search_null_filter, "filter_get_search_null_filter");
    RUN_TEST(test_filter_clone_with_search, "filter_clone_with_search");
    RUN_TEST(test_filter_clone_no_search, "filter_clone_no_search");
    RUN_TEST(test_filter_matches_with_search_callback, "filter_matches_with_search_callback");
    RUN_TEST(test_filter_matches_with_search_no_callback, "filter_matches_with_search_no_callback");
    RUN_TEST(test_filter_matches_with_search_empty_search, "filter_matches_with_search_empty_search");
    RUN_TEST(test_filter_matches_without_search, "filter_matches_without_search");
    RUN_TEST(test_filter_matches_search_with_kind_filter, "filter_matches_search_with_kind_filter");
    RUN_TEST(test_filters_match_with_search, "filters_match_with_search");
    RUN_TEST(test_filter_matches_basic_still_works, "filter_matches_basic_still_works");
    RUN_TEST(test_client_msg_parse_req_with_search, "client_msg_parse_req_with_search");
    RUN_TEST(test_client_msg_parse_multiple_filters_with_search, "client_msg_parse_multiple_filters_with_search");
    RUN_TEST(test_search_with_extensions, "search_with_extensions");
#endif

#ifndef HAVE_UNITY
    if (g_tests_failed_count > 0) {
        printf("FAILED: %d test(s) failed!\n", g_tests_failed_count);
        return g_tests_failed_count;
    }
#endif
    printf("All NIP-50 tests passed!\n");
    return 0;
}

#else

int run_nip50_tests(void)
{
    printf("NIP-50 tests skipped (NOSTR_FEATURE_JSON_ENHANCED not enabled)\n");
    return 0;
}

#endif

#ifndef TEST_RUNNER_INCLUDED
int main(void)
{
    nostr_init();
    int result = run_nip50_tests();
    nostr_cleanup();
    return result;
}
#endif
