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

extern void run_relay_protocol_core_tests(void);
extern void run_relay_protocol_json_tests(void);
extern void run_relay_protocol_nip_tests(void);
extern void run_relay_protocol_accessor_tests(void);

int main(void)
{
    nostr_init();

    run_relay_protocol_core_tests();
    run_relay_protocol_json_tests();
    run_relay_protocol_nip_tests();
    run_relay_protocol_accessor_tests();

    printf("\nAll relay protocol tests passed!\n");

    nostr_cleanup();
    return 0;
}
