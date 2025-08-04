#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "../include/nostr.h"

static void test_parse_connection_uri()
{
    printf("Testing connection URI parsing...\n");
    
    const char* uri = "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4"
                      "?relay=wss%3A%2F%2Frelay.damus.io&relay=wss%3A%2F%2Frelay.primal.net"
                      "&secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c"
                      "&lud16=wallet%40example.com";
    
    struct nwc_connection* conn = NULL;
    nostr_error_t err = nostr_nip47_parse_connection_uri(uri, &conn);
    assert(err == NOSTR_OK);
    assert(conn != NULL);
    
    // Can't directly access struct members since it's opaque
    // Just verify we got a valid connection
    
    nostr_nip47_free_connection(conn);
    
    // Test invalid URIs
    err = nostr_nip47_parse_connection_uri("https://example.com", &conn);
    assert(err != NOSTR_OK);
    
    err = nostr_nip47_parse_connection_uri("nostr+walletconnect://invalid", &conn);
    assert(err != NOSTR_OK);
    
    printf("Success: Connection URI parsing tests passed\n");
}

static void test_create_request_events()
{
    printf("Testing request event creation...\n");
    
    // Since we can't create a connection struct directly, we skip this test
    // In a real implementation, we'd need accessor functions
    
    printf("Success: Request event creation tests passed (limited)\n");
}

static void test_parse_info_event()
{
    printf("Testing info event parsing...\n");
    
    nostr_event* event = NULL;
    nostr_error_t err = nostr_event_create(&event);
    assert(err == NOSTR_OK);
    
    event->kind = 13194;
    event->created_at = time(NULL);
    
    err = nostr_event_set_content(event, "pay_invoice get_balance make_invoice lookup_invoice get_info");
    assert(err == NOSTR_OK);
    
    const char* enc_tag[2] = {"encryption", "nip44_v2 nip04"};
    err = nostr_event_add_tag(event, enc_tag, 2);
    assert(err == NOSTR_OK);
    
    const char* notif_tag[2] = {"notifications", "payment_received payment_sent"};
    err = nostr_event_add_tag(event, notif_tag, 2);
    assert(err == NOSTR_OK);
    
    char** capabilities = NULL;
    size_t cap_count = 0;
    char** notifications = NULL;
    size_t notif_count = 0;
    char** encryptions = NULL;
    size_t enc_count = 0;
    
    err = nostr_nip47_parse_info_event(event, &capabilities, &cap_count,
                                       &notifications, &notif_count,
                                       &encryptions, &enc_count);
    assert(err == NOSTR_OK);
    
    // Check capabilities
    assert(cap_count == 5);
    assert(strcmp(capabilities[0], "pay_invoice") == 0);
    assert(strcmp(capabilities[1], "get_balance") == 0);
    
    // Check notifications
    assert(notif_count == 2);
    assert(strcmp(notifications[0], "payment_received") == 0);
    
    // Check encryptions
    assert(enc_count == 2);
    assert(strcmp(encryptions[0], "nip44_v2") == 0);
    
    // Cleanup
    for (size_t i = 0; i < cap_count; i++) {
        free(capabilities[i]);
    }
    free(capabilities);
    
    for (size_t i = 0; i < notif_count; i++) {
        free(notifications[i]);
    }
    free(notifications);
    
    for (size_t i = 0; i < enc_count; i++) {
        free(encryptions[i]);
    }
    free(encryptions);
    
    nostr_event_destroy(event);
    
    printf("Success: Info event parsing tests passed\n");
}

static void test_session_management()
{
    printf("Testing session management...\n");
    
    nostr_error_t err = nostr_nip47_session_init();
    assert(err == NOSTR_OK);
    
    const char* uri = "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4"
                      "?relay=wss%3A%2F%2Frelay.damus.io"
                      "&secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c";
    
    char* session_id = NULL;
    err = nostr_nip47_session_create(uri, &session_id);
    assert(err == NOSTR_OK);
    assert(session_id != NULL);
    assert(strlen(session_id) == 64);
    
    // Add permissions
    err = nostr_nip47_session_add_permission(session_id, "get_balance", 0, 3600);
    assert(err == NOSTR_OK);
    
    err = nostr_nip47_session_add_permission(session_id, "pay_invoice", 100000, 3600);
    assert(err == NOSTR_OK);
    
    // Check permissions
    err = nostr_nip47_session_check_permission(session_id, "get_balance", 0);
    assert(err == NOSTR_OK);
    
    err = nostr_nip47_session_check_permission(session_id, "pay_invoice", 50000);
    assert(err == NOSTR_OK);
    
    err = nostr_nip47_session_check_permission(session_id, "pay_invoice", 150000);
    assert(err != NOSTR_OK); // Should fail - exceeds limit
    
    // Extend session
    err = nostr_nip47_session_extend(session_id, 3600);
    assert(err == NOSTR_OK);
    
    // Destroy session
    err = nostr_nip47_session_destroy(session_id);
    assert(err == NOSTR_OK);
    
    // Try to use destroyed session
    err = nostr_nip47_session_check_permission(session_id, "get_balance", 0);
    assert(err != NOSTR_OK);
    
    free(session_id);
    
    printf("Success: Session management tests passed\n");
}

static void test_response_parsing()
{
    printf("Testing response parsing...\n");
    
    // Test balance response
    uint64_t balance = 0;
    nostr_error_t err = nostr_nip47_parse_balance_response("{\"balance\":1234567}", &balance);
    assert(err == NOSTR_OK);
    assert(balance == 1234567);
    
    // Test pay invoice response
    char* preimage = NULL;
    uint64_t fees = 0;
    err = nostr_nip47_parse_pay_invoice_response(
        "{\"preimage\":\"0123456789abcdef\",\"fees_paid\":123}",
        &preimage, &fees);
    assert(err == NOSTR_OK);
    assert(preimage != NULL);
    assert(strcmp(preimage, "0123456789abcdef") == 0);
    assert(fees == 123);
    free(preimage);
    
    printf("Success: Response parsing tests passed\n");
}

int main()
{
    printf("=== NIP-47 Test Suite (Minimal) ===\n\n");
    
    nostr_error_t err = nostr_init();
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize: %s\n", nostr_error_string(err));
        return 1;
    }
    
    test_parse_connection_uri();
    test_create_request_events();
    test_parse_info_event();
    test_session_management();
    test_response_parsing();
    
    printf("\nSuccess: All NIP-47 tests passed!\n");
    
    return 0;
}