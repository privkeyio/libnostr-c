#ifndef UNITY_H
#define UNITY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_failed = 0;

#define UNITY_BEGIN() do { \
    printf("Running tests...\n"); \
    tests_run = 0; \
    tests_failed = 0; \
} while(0)

#ifdef _MSC_VER
/* MSVC doesn't support statement expressions, use function approach */
static inline int unity_end_func(void) {
    printf("\nTests: %d, Failures: %d\n", tests_run, tests_failed);
    return tests_failed;
}
#define UNITY_END() unity_end_func()
#else
/* GCC/Clang support statement expressions */
#define UNITY_END() ({ \
    printf("\nTests: %d, Failures: %d\n", tests_run, tests_failed); \
    tests_failed; \
})
#endif

#define RUN_TEST(func) do { \
    printf("."); \
    fflush(stdout); \
    tests_run++; \
    func(); \
} while(0)

#define TEST_ASSERT(condition) do { \
    if (!(condition)) { \
        printf("\nFAIL: %s:%d - %s\n", __FILE__, __LINE__, #condition); \
        tests_failed++; \
    } \
} while(0)

#define TEST_ASSERT_EQUAL(expected, actual) do { \
    if ((expected) != (actual)) { \
        printf("\nFAIL: %s:%d - Expected %d, got %d\n", __FILE__, __LINE__, (int)(expected), (int)(actual)); \
        tests_failed++; \
    } \
} while(0)

#define TEST_ASSERT_EQUAL_STRING(expected, actual) do { \
    if (strcmp((expected), (actual)) != 0) { \
        printf("\nFAIL: %s:%d - Expected '%s', got '%s'\n", __FILE__, __LINE__, (expected), (actual)); \
        tests_failed++; \
    } \
} while(0)

#define TEST_ASSERT_EQUAL_MEMORY(expected, actual, len) do { \
    if (memcmp((expected), (actual), (len)) != 0) { \
        printf("\nFAIL: %s:%d - Memory content differs\n", __FILE__, __LINE__); \
        tests_failed++; \
    } \
} while(0)

#define TEST_ASSERT_NOT_NULL(ptr) do { \
    if ((ptr) == NULL) { \
        printf("\nFAIL: %s:%d - Expected non-NULL pointer\n", __FILE__, __LINE__); \
        tests_failed++; \
    } \
} while(0)

#define TEST_ASSERT_NULL(ptr) do { \
    if ((ptr) != NULL) { \
        printf("\nFAIL: %s:%d - Expected NULL pointer\n", __FILE__, __LINE__); \
        tests_failed++; \
    } \
} while(0)

#define TEST_ASSERT_TRUE(condition) TEST_ASSERT(condition)
#define TEST_ASSERT_FALSE(condition) TEST_ASSERT(!(condition))
#define TEST_ASSERT_NOT_EQUAL(expected, actual) TEST_ASSERT((expected) != (actual))

#endif