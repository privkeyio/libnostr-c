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
    
    // Check service pubkey
    uint8_t expected_pubkey[32] = {
        0xb8, 0x89, 0xff, 0x5b, 0x15, 0x13, 0xb6, 0x41,
        0xe2, 0xa1, 0x39, 0xf6, 0x61, 0xa6, 0x61, 0x36,
        0x49, 0x79, 0xc5, 0xbe, 0xee, 0x91, 0x84, 0x2f,
        0x8f, 0x0e, 0xf4, 0x2a, 0xb5, 0x58, 0xe9, 0xd4
    };
    assert(memcmp(conn->service_pubkey.data, expected_pubkey, 32) == 0);
    
    // Check relays
    assert(conn->relay_count == 2);
    assert(strcmp(conn->relays[0], "wss://relay.damus.io") == 0);
    assert(strcmp(conn->relays[1], "wss://relay.primal.net") == 0);
    
    // Check secret
    uint8_t expected_secret[32] = {
        0x71, 0xa8, 0xc1, 0x4c, 0x14, 0x07, 0xc1, 0x13,
        0x60, 0x10, 0x79, 0xc4, 0x30, 0x2d, 0xab, 0x36,
        0x46, 0x0f, 0x0c, 0xcd, 0x0a, 0xd5, 0x06, 0xf1,
        0xf2, 0xdc, 0x73, 0xb5, 0x10, 0x0e, 0x4f, 0x3c
    };
    assert(memcmp(conn->secret.data, expected_secret, 32) == 0);
    
    // Check lud16
    assert(conn->lud16 != NULL);
    assert(strcmp(conn->lud16, "wallet@example.com") == 0);
    
    nostr_nip47_free_connection(conn);
    
    // Test invalid URIs
    err = nostr_nip47_parse_connection_uri("https://example.com", &conn);
    assert(err != NOSTR_OK);
    
    err = nostr_nip47_parse_connection_uri("nostr+walletconnect://invalid", &conn);
    assert(err != NOSTR_OK);
    
    err = nostr_nip47_parse_connection_uri(
        "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4",
        &conn);
    assert(err != NOSTR_OK); // Missing required parameters
    
    printf("Success: Connection URI parsing tests passed\n");
}

static void test_create_request_events()
{
    printf("Testing request event creation...\n");
    
    struct nwc_connection conn = {0};
    
    // Setup mock connection
    memset(conn.service_pubkey.data, 0xAA, 32);
    memset(conn.secret.data, 0xBB, 32);
    
    // Test get_balance request
    char* params = NULL;
    nostr_error_t err = nostr_nip47_create_get_balance_params(&params);
    assert(err == NOSTR_OK);
    assert(params != NULL);
    assert(strcmp(params, "{}") == 0);
    
    nostr_event* event = NULL;
    err = nostr_nip47_create_request_event(&event, &conn, "get_balance", params, 1);
    assert(err == NOSTR_OK);
    assert(event != NULL);
    assert(event->kind == 23194);
    assert(event->content != NULL);
    
    free(params);
    nostr_event_destroy(event);
    
    // Test pay_invoice request
    uint64_t amount = 100000;
    err = nostr_nip47_create_pay_invoice_params(&params, "lnbc123...", &amount);
    assert(err == NOSTR_OK);
    assert(params != NULL);
    assert(strstr(params, "\"invoice\":\"lnbc123...\"") != NULL);
    assert(strstr(params, "\"amount\":100000") != NULL);
    
    err = nostr_nip47_create_request_event(&event, &conn, "pay_invoice", params, 1);
    assert(err == NOSTR_OK);
    assert(event != NULL);
    
    // Check encryption tag
    int found_enc_tag = 0;
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count >= 2 && strcmp(event->tags[i].values[0], "encryption") == 0) {
            assert(strcmp(event->tags[i].values[1], "nip44_v2") == 0);
            found_enc_tag = 1;
            break;
        }
    }
    assert(found_enc_tag);
    
    free(params);
    nostr_event_destroy(event);
    
    // Test make_invoice request
    uint32_t expiry = 3600;
    err = nostr_nip47_create_make_invoice_params(&params, 50000, "Test", NULL, &expiry);
    assert(err == NOSTR_OK);
    assert(params != NULL);
    assert(strstr(params, "\"amount\":50000") != NULL);
    assert(strstr(params, "\"description\":\"Test\"") != NULL);
    assert(strstr(params, "\"expiry\":3600") != NULL);
    
    free(params);
    
    printf("Success: Request event creation tests passed\n");
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
    assert(strcmp(capabilities[2], "make_invoice") == 0);
    assert(strcmp(capabilities[3], "lookup_invoice") == 0);
    assert(strcmp(capabilities[4], "get_info") == 0);
    
    // Check notifications
    assert(notif_count == 2);
    assert(strcmp(notifications[0], "payment_received") == 0);
    assert(strcmp(notifications[1], "payment_sent") == 0);
    
    // Check encryptions
    assert(enc_count == 2);
    assert(strcmp(encryptions[0], "nip44_v2") == 0);
    assert(strcmp(encryptions[1], "nip04") == 0);
    
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
    
    err = nostr_nip47_session_check_permission(session_id, "make_invoice", 0);
    assert(err != NOSTR_OK); // Should fail - no permission
    
    // Get connection
    struct nwc_connection* conn = NULL;
    err = nostr_nip47_session_get_connection(session_id, &conn);
    assert(err == NOSTR_OK);
    assert(conn != NULL);
    
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
    
    // Test info response
    char* alias = NULL;
    char* color = NULL;
    char* pubkey = NULL;
    char* network = NULL;
    uint32_t height = 0;
    char** methods = NULL;
    size_t method_count = 0;
    
    const char* info_json = "{\"alias\":\"MyWallet\",\"color\":\"#FF0000\","
                           "\"pubkey\":\"abc123\",\"network\":\"mainnet\","
                           "\"block_height\":800000,"
                           "\"methods\":[\"pay_invoice\",\"get_balance\"]}";
    
    err = nostr_nip47_parse_info_response(info_json, &alias, &color, &pubkey,
                                          &network, &height, &methods, &method_count);
    assert(err == NOSTR_OK);
    
#ifdef HAVE_CJSON
    assert(alias != NULL && strcmp(alias, "MyWallet") == 0);
    assert(color != NULL && strcmp(color, "#FF0000") == 0);
    assert(pubkey != NULL && strcmp(pubkey, "abc123") == 0);
    assert(network != NULL && strcmp(network, "mainnet") == 0);
    assert(height == 800000);
    assert(method_count == 2);
    assert(methods != NULL);
    assert(strcmp(methods[0], "pay_invoice") == 0);
    assert(strcmp(methods[1], "get_balance") == 0);
    
    for (size_t i = 0; i < method_count; i++) {
        free(methods[i]);
    }
    free(methods);
#endif
    
    free(alias);
    free(color);
    free(pubkey);
    free(network);
    
    printf("Success: Response parsing tests passed\n");
}

static void test_multi_pay_commands()
{
    printf("Testing multi-pay commands...\n");
    
    const char* ids[] = {"id1", "id2", "id3"};
    const char* invoices[] = {"lnbc1...", "lnbc2...", "lnbc3..."};
    uint64_t amounts[] = {1000, 2000, 3000};
    
    char* params = NULL;
    nostr_error_t err = nostr_nip47_create_multi_pay_invoice_params(&params, ids, invoices, 
                                                                    amounts, 3);
    assert(err == NOSTR_OK);
    assert(params != NULL);
    assert(strstr(params, "\"invoices\":[") != NULL);
    assert(strstr(params, "\"id\":\"id1\"") != NULL);
    assert(strstr(params, "\"invoice\":\"lnbc1...\"") != NULL);
    assert(strstr(params, "\"amount\":1000") != NULL);
    
    free(params);
    
    // Test keysend
    const char* tlv[] = {"696969", "77616c5f6872444873305242454d353736"};
    err = nostr_nip47_create_pay_keysend_params(&params, 5000, "03abc...", 
                                                 "preimage123", tlv, 2);
    assert(err == NOSTR_OK);
    assert(params != NULL);
    assert(strstr(params, "\"amount\":5000") != NULL);
    assert(strstr(params, "\"pubkey\":\"03abc...\"") != NULL);
    assert(strstr(params, "\"preimage\":\"preimage123\"") != NULL);
    assert(strstr(params, "\"tlv_records\":[") != NULL);
    
    free(params);
    
    printf("Success: Multi-pay command tests passed\n");
}

int main()
{
    printf("=== NIP-47 Test Suite ===\n\n");
    
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
    test_multi_pay_commands();
    
    printf("\nSuccess: All NIP-47 tests passed!\n");
    
    return 0;
}