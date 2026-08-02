/*
 * On-target smoke test.
 *
 * Built by CI and, under QEMU, actually run. That distinction is the point: the
 * mbedTLS RNG path is compiled only for ESP targets, and until this ran it had
 * never executed anywhere. Three defects reached main through that gap, and
 * each has a case here:
 *
 *   - a self-deadlock, where nostr_init() held its context lock and the RNG
 *     took the same non-recursive lock
 *   - an unsynchronised mbedtls_ctr_drbg_random() draw, whose internal mutex
 *     compiles out because ESP-IDF leaves MBEDTLS_THREADING_C off
 *   - a >1024-byte regression, since mbedtls_ctr_drbg_random() refuses more
 *     than MBEDTLS_CTR_DRBG_MAX_REQUEST and does not split internally
 *
 * The host suite covers the same logic against mbedTLS 2.x. This covers the 3.x
 * ESP-IDF actually ships, on the FreeRTOS scheduler the race needs.
 *
 * The result is one line. CI greps for it, so a silent hang or a crash is a
 * failure rather than a pass.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "nostr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#define DRAW_TASKS 4
#define DRAWS_PER_TASK 16
#define DRAW_LEN 32

static uint8_t g_draws[DRAW_TASKS][DRAWS_PER_TASK][DRAW_LEN];
static int g_task_failures[DRAW_TASKS];
static SemaphoreHandle_t g_done;

static int failures = 0;

static void check(int ok, const char *what) {
    if (!ok) {
        printf("SMOKE-FAIL: %s\n", what);
        failures++;
    } else {
        printf("  ok: %s\n", what);
    }
}

static int all_zero(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (b[i]) return 0;
    }
    return 1;
}

static void draw_task(void *arg) {
    int t = (int)(intptr_t)arg;
    for (int i = 0; i < DRAWS_PER_TASK; i++) {
        if (nostr_random_bytes(g_draws[t][i], DRAW_LEN) != 1) {
            g_task_failures[t]++;
        }
    }
    xSemaphoreGive(g_done);
    vTaskDelete(NULL);
}

void app_main(void) {
    printf("SMOKE-BEGIN\n");

    /* Deadlock case: nostr_init() seeds through the same path the RNG uses. A
     * regression here hangs rather than fails, which is why CI bounds the run. */
    check(nostr_init() == NOSTR_OK, "nostr_init");

    uint8_t buf[DRAW_LEN];
    memset(buf, 0, sizeof(buf));
    check(nostr_random_bytes(buf, sizeof(buf)) == 1 && !all_zero(buf, sizeof(buf)),
          "draw after init does not deadlock and fills the buffer");

    /* Chunking case: one request past MBEDTLS_CTR_DRBG_MAX_REQUEST. An
     * unchunked implementation fails here while passing every 32-byte draw. */
    static uint8_t big[4096];
    memset(big, 0, sizeof(big));
    check(nostr_random_bytes(big, sizeof(big)) == 1, "draw of 4096 bytes succeeds");
    check(!all_zero(big + 1024, sizeof(big) - 1024),
          "bytes past the 1024-byte DRBG limit are filled");

    /* Race case: concurrent draws on a dual-core part. Without an external lock
     * two tasks can be handed the same AES-CTR block, so duplicates are the
     * observable symptom. */
    memset(g_draws, 0, sizeof(g_draws));
    memset(g_task_failures, 0, sizeof(g_task_failures));
    g_done = xSemaphoreCreateCounting(DRAW_TASKS, 0);
    check(g_done != NULL, "semaphore created");

    int started = 0;
    for (int t = 0; t < DRAW_TASKS; t++) {
        /* 4096 is generous on purpose: ctr_drbg_reseed_internal puts a
         * 384-byte seed buffer on the caller's stack, plus the entropy gather. */
        if (xTaskCreate(draw_task, "draw", 4096, (void *)(intptr_t)t, 5, NULL) == pdPASS) {
            started++;
        }
    }
    /* Unchecked, a failed create meant one fewer xSemaphoreGive and a
     * portMAX_DELAY wait that never returns: a CI timeout with no message,
     * which is the failure mode this whole file exists to avoid. */
    check(started == DRAW_TASKS, "all draw tasks were created");

    int joined = 0;
    for (int t = 0; t < started; t++) {
        /* Bounded rather than portMAX_DELAY, so a task that hangs reports a
         * missing result instead of stalling the run to the job timeout. */
        if (xSemaphoreTake(g_done, pdMS_TO_TICKS(10000)) == pdTRUE) {
            joined++;
        }
    }
    check(joined == started, "every draw task finished within the timeout");

    int draw_errors = 0;
    for (int t = 0; t < DRAW_TASKS; t++) draw_errors += g_task_failures[t];
    check(draw_errors == 0, "every concurrent draw reported success");

    const int total = DRAW_TASKS * DRAWS_PER_TASK;
    const uint8_t *flat = (const uint8_t *)g_draws;
    int dup = 0, zero = 0;
    for (int i = 0; i < total; i++) {
        if (all_zero(flat + (size_t)i * DRAW_LEN, DRAW_LEN)) zero++;
        for (int j = i + 1; j < total; j++) {
            if (memcmp(flat + (size_t)i * DRAW_LEN,
                       flat + (size_t)j * DRAW_LEN, DRAW_LEN) == 0) dup++;
        }
    }
    check(zero == 0, "no concurrent draw returned all zeros");
    check(dup == 0, "no two concurrent draws returned identical bytes");

    /* The public API the RNG feeds. */
    nostr_keypair kp;
    check(nostr_keypair_generate(&kp) == NOSTR_OK, "nostr_keypair_generate");
    nostr_keypair_destroy(&kp);

    if (failures == 0) {
        printf("SMOKE-PASS\n");
    } else {
        printf("SMOKE-FAIL-TOTAL %d\n", failures);
    }
}
