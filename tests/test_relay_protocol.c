/**
 * @file test_relay_protocol.c
 * @brief Combined test runner for all relay protocol tests
 *
 * This file runs all relay protocol tests from:
 *   - test_relay_protocol_core.c (validation, kinds, event helpers)
 *   - test_relay_protocol_json.c (filters, client messages, serialization)
 *   - test_relay_protocol_nip.c (NIP-09 deletion, NIP-11 relay info)
 *   - test_relay_protocol_accessors.c (hex, filter/event/message accessors)
 */

#ifdef HAVE_UNITY
#include "unity.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include "../include/nostr.h"
#include "../include/nostr_relay_protocol.h"

#ifdef HAVE_UNITY
void setUp(void) {}
void tearDown(void) {}
#endif

extern int run_relay_protocol_core_tests(void);
extern int run_relay_protocol_json_tests(void);
extern int run_relay_protocol_nip_tests(void);
extern int run_relay_protocol_accessor_tests(void);

int main(void)
{
    nostr_init();

    int r1 = run_relay_protocol_core_tests();
    int r2 = run_relay_protocol_json_tests();
    int r3 = run_relay_protocol_nip_tests();
    int r4 = run_relay_protocol_accessor_tests();

    int result = r1 || r2 || r3 || r4;

    if (result == 0) {
        printf("\nAll relay protocol tests passed!\n");
    } else {
        printf("\nSome tests failed!\n");
    }

    nostr_cleanup();
    return result;
}
