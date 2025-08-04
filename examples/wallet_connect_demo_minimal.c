#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include "../include/nostr.h"

int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <nostr+walletconnect://...>\n", argv[0]);
        return 1;
    }
    
    nostr_error_t err;
    
    err = nostr_init();
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize: %s\n", nostr_error_string(err));
        return 1;
    }
    
    printf("=== NIP-47 Wallet Connect Demo ===\n\n");
    
    // Parse connection URI
    struct nwc_connection* conn = NULL;
    err = nostr_nip47_parse_connection_uri(argv[1], &conn);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to parse URI: %s\n", nostr_error_string(err));
        return 1;
    }
    
    printf("Connection established successfully\n\n");
    
    // Initialize session management
    err = nostr_nip47_session_init();
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to init sessions: %s\n", nostr_error_string(err));
        nostr_nip47_free_connection(conn);
        return 1;
    }
    
    // Create a session
    char* session_id = NULL;
    err = nostr_nip47_session_create(argv[1], &session_id);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to create session: %s\n", nostr_error_string(err));
        nostr_nip47_free_connection(conn);
        return 1;
    }
    
    printf("Session created: %s\n\n", session_id);
    
    // Add permissions
    err = nostr_nip47_session_add_permission(session_id, "get_balance", 0, 3600);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to add permission: %s\n", nostr_error_string(err));
    }
    
    err = nostr_nip47_session_add_permission(session_id, "pay_invoice", 100000, 3600);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to add permission: %s\n", nostr_error_string(err));
    }
    
    printf("Permissions added:\n");
    printf("  - get_balance (unlimited)\n");
    printf("  - pay_invoice (100,000 msats limit)\n\n");
    
    // Demo 1: Get wallet info
    printf("--- Demo 1: Get Wallet Info ---\n");
    
    char* info_params = NULL;
    err = nostr_nip47_create_get_info_params(&info_params);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to create params: %s\n", nostr_error_string(err));
        goto cleanup;
    }
    
    nostr_event* info_request = NULL;
    err = nostr_nip47_create_request_event(&info_request, conn, "get_info", info_params, 1);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to create request: %s\n", nostr_error_string(err));
        free(info_params);
        goto cleanup;
    }
    
    printf("Request event created:\n");
    printf("  Kind: %d\n", info_request->kind);
    printf("  Encrypted content length: %zu\n\n", strlen(info_request->content));
    
    free(info_params);
    nostr_event_destroy(info_request);
    
    // Demo 2: Get balance
    printf("--- Demo 2: Get Balance ---\n");
    
    if (nostr_nip47_session_check_permission(session_id, "get_balance", 0) != NOSTR_OK) {
        fprintf(stderr, "Permission denied for get_balance\n");
        goto cleanup;
    }
    
    char* balance_params = NULL;
    err = nostr_nip47_create_get_balance_params(&balance_params);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to create params: %s\n", nostr_error_string(err));
        goto cleanup;
    }
    
    nostr_event* balance_request = NULL;
    err = nostr_nip47_create_request_event(&balance_request, conn, "get_balance", balance_params, 1);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to create request: %s\n", nostr_error_string(err));
        free(balance_params);
        goto cleanup;
    }
    
    printf("Balance request created (would be sent to relay)\n\n");
    
    free(balance_params);
    nostr_event_destroy(balance_request);
    
    // Demo 3: Create invoice
    printf("--- Demo 3: Create Invoice ---\n");
    
    char* invoice_params = NULL;
    uint32_t expiry = 3600;
    err = nostr_nip47_create_make_invoice_params(&invoice_params, 50000, 
                                                 "Test payment", NULL, &expiry);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to create params: %s\n", nostr_error_string(err));
        goto cleanup;
    }
    
    nostr_event* invoice_request = NULL;
    err = nostr_nip47_create_request_event(&invoice_request, conn, "make_invoice", 
                                          invoice_params, 1);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to create request: %s\n", nostr_error_string(err));
        free(invoice_params);
        goto cleanup;
    }
    
    printf("Invoice request created:\n");
    printf("  Amount: 50,000 msats\n");
    printf("  Description: Test payment\n");
    printf("  Expiry: 3600 seconds\n\n");
    
    free(invoice_params);
    nostr_event_destroy(invoice_request);
    
    // Demo 4: Pay invoice (with permission check)
    printf("--- Demo 4: Pay Invoice ---\n");
    
    const char* test_invoice = "lnbc50n1...";
    uint64_t amount = 50000;
    
    if (nostr_nip47_session_check_permission(session_id, "pay_invoice", amount) != NOSTR_OK) {
        fprintf(stderr, "Permission denied: exceeds spending limit\n");
    } else {
        printf("Permission granted for 50,000 msats payment\n");
        
        char* pay_params = NULL;
        err = nostr_nip47_create_pay_invoice_params(&pay_params, test_invoice, &amount);
        if (err != NOSTR_OK) {
            fprintf(stderr, "Failed to create params: %s\n", nostr_error_string(err));
            goto cleanup;
        }
        
        nostr_event* pay_request = NULL;
        err = nostr_nip47_create_request_event(&pay_request, conn, "pay_invoice", 
                                              pay_params, 1);
        if (err != NOSTR_OK) {
            fprintf(stderr, "Failed to create request: %s\n", nostr_error_string(err));
            free(pay_params);
            goto cleanup;
        }
        
        printf("Payment request created for invoice: %s\n\n", test_invoice);
        
        free(pay_params);
        nostr_event_destroy(pay_request);
    }
    
    // Demo 5: Parse mock response
    printf("--- Demo 5: Parse Mock Response ---\n");
    
    const char* mock_result = "{\"balance\":1000000}";
    
    printf("Mock balance response: %s\n", mock_result);
    
    uint64_t balance = 0;
    err = nostr_nip47_parse_balance_response(mock_result, &balance);
    if (err == NOSTR_OK) {
        printf("Parsed balance: %llu msats\n", (unsigned long long)balance);
    }
    
    printf("\nSuccess: NIP-47 demo completed successfully!\n");
    
cleanup:
    if (session_id) {
        nostr_nip47_session_destroy(session_id);
        free(session_id);
    }
    
    nostr_nip47_free_connection(conn);
    
    return 0;
}