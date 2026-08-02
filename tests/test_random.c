/*
 * Tests for nostr_random_bytes().
 *
 * This function produces every private key (nostr_key_generate), BIP-39
 * mnemonic (hd_key.c), BIP-340 aux_rand (event.c) and NIP-44 nonce, and had no
 * direct test on any platform. Three defects shipped through that gap: a
 * self-deadlock, an unsynchronised DRBG draw, and a length regression. Each
 * case below is a regression test for one of them.
 */
#include "unity.h"
#include "../include/nostr.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * A minimal thread shim. The concurrency case below is the regression test for
 * an unsynchronised DRBG draw, and the RNG takes a different lock on Windows
 * (CRITICAL_SECTION) than on POSIX, so the case is worth running on both rather
 * than compiling it out for MSVC, which has no pthread.h.
 */
#ifdef _WIN32
#include <windows.h>
typedef HANDLE thread_t;
typedef DWORD WINAPI thread_ret_t;
#define THREAD_CALL WINAPI
static int thread_start(thread_t *t, thread_ret_t(THREAD_CALL *fn)(void *), void *arg) {
    *t = CreateThread(NULL, 0, fn, arg, 0, NULL);
    return *t == NULL ? -1 : 0;
}
static void thread_join(thread_t t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
#define THREAD_RETURN return 0
#else
#include <pthread.h>
typedef pthread_t thread_t;
typedef void *thread_ret_t;
#define THREAD_CALL
static int thread_start(thread_t *t, thread_ret_t(THREAD_CALL *fn)(void *), void *arg) {
    return pthread_create(t, NULL, fn, arg);
}
static void thread_join(thread_t t) { pthread_join(t, NULL); }
#define THREAD_RETURN return NULL
#endif

void setUp(void) {}
void tearDown(void) {}

static int all_zero(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (b[i]) return 0;
    }
    return 1;
}

static void test_fills_the_buffer(void) {
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    TEST_ASSERT_EQUAL(1, nostr_random_bytes(buf, sizeof(buf)));
    TEST_ASSERT_FALSE(all_zero(buf, sizeof(buf)));
}

/*
 * The length regression. mbedtls_ctr_drbg_random() refuses more than
 * MBEDTLS_CTR_DRBG_MAX_REQUEST (1024) bytes and does not split internally, so
 * an unchunked implementation fails above 1KB while passing every 32-byte test.
 * The tail is checked separately: a partial fill would leave it zeroed while
 * the call still reported success.
 */
static void test_draws_larger_than_the_drbg_request_limit(void) {
    const size_t n = 4096;
    uint8_t *buf = calloc(1, n);
    TEST_ASSERT_NOT_NULL(buf);

    TEST_ASSERT_EQUAL(1, nostr_random_bytes(buf, n));
    TEST_ASSERT_FALSE(all_zero(buf, n));
    /* Past the 1024-byte boundary, where a single-request implementation stops. */
    TEST_ASSERT_FALSE(all_zero(buf + 1024, n - 1024));
    TEST_ASSERT_FALSE(all_zero(buf + n - 64, 64));

    free(buf);
}

static void test_successive_draws_differ(void) {
    uint8_t a[32], b[32];
    TEST_ASSERT_EQUAL(1, nostr_random_bytes(a, sizeof(a)));
    TEST_ASSERT_EQUAL(1, nostr_random_bytes(b, sizeof(b)));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(a, b, sizeof(a)));
}

static void test_zero_length_is_not_an_error(void) {
    uint8_t buf[1] = {0xAA};
    TEST_ASSERT_EQUAL(1, nostr_random_bytes(buf, 0));
    TEST_ASSERT_EQUAL(0xAA, buf[0]);
}

/*
 * The data race. mbedtls_ctr_drbg_random() mutates the generator's counter and
 * key, and its internal mutex compiles out unless MBEDTLS_THREADING_C is set,
 * which ESP-IDF leaves off. Without an external lock two concurrent callers can
 * be handed the same AES-CTR block: identical private keys or identical
 * aux_rand. Duplicates across threads are the observable symptom.
 */
#define RNG_THREADS 8
#define RNG_DRAWS_PER_THREAD 64
#define RNG_DRAW_LEN 32

static uint8_t g_draws[RNG_THREADS][RNG_DRAWS_PER_THREAD][RNG_DRAW_LEN];
static int g_failures[RNG_THREADS];

static thread_ret_t THREAD_CALL draw_thread(void *arg) {
    intptr_t t = (intptr_t)arg;
    for (int i = 0; i < RNG_DRAWS_PER_THREAD; i++) {
        if (nostr_random_bytes(g_draws[t][i], RNG_DRAW_LEN) != 1) {
            g_failures[t]++;
        }
    }
    THREAD_RETURN;
}

static void test_concurrent_draws_are_all_distinct(void) {
    thread_t th[RNG_THREADS];

    memset(g_draws, 0, sizeof(g_draws));
    memset(g_failures, 0, sizeof(g_failures));

    for (intptr_t t = 0; t < RNG_THREADS; t++) {
        TEST_ASSERT_EQUAL(0, thread_start(&th[t], draw_thread, (void *)t));
    }
    for (int t = 0; t < RNG_THREADS; t++) {
        thread_join(th[t]);
    }
    for (int t = 0; t < RNG_THREADS; t++) {
        TEST_ASSERT_EQUAL(0, g_failures[t]);
    }

    /* O(n^2) over 512 draws is trivial here and needs no allocation or sort. */
    const int total = RNG_THREADS * RNG_DRAWS_PER_THREAD;
    const uint8_t *flat = (const uint8_t *)g_draws;
    for (int i = 0; i < total; i++) {
        TEST_ASSERT_FALSE(all_zero(flat + (size_t)i * RNG_DRAW_LEN, RNG_DRAW_LEN));
        for (int j = i + 1; j < total; j++) {
            if (memcmp(flat + (size_t)i * RNG_DRAW_LEN,
                       flat + (size_t)j * RNG_DRAW_LEN, RNG_DRAW_LEN) == 0) {
                /* two concurrent draws returned identical bytes */
                TEST_ASSERT(0);
            }
        }
    }
}

/*
 * The self-deadlock. nostr_init() holds its context lock while seeding, and the
 * RNG once took that same non-recursive lock, so the first call hung forever.
 * Drawing after init exercises the ordering that regressed.
 */
static void test_draw_after_init_does_not_deadlock(void) {
    uint8_t buf[32];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_init());
    TEST_ASSERT_EQUAL(1, nostr_random_bytes(buf, sizeof(buf)));
    TEST_ASSERT_FALSE(all_zero(buf, sizeof(buf)));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_fills_the_buffer);
    RUN_TEST(test_draws_larger_than_the_drbg_request_limit);
    RUN_TEST(test_successive_draws_differ);
    RUN_TEST(test_zero_length_is_not_an_error);
    RUN_TEST(test_concurrent_draws_are_all_distinct);
    RUN_TEST(test_draw_after_init_does_not_deadlock);
    return UNITY_END();
}
