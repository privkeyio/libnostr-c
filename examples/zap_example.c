#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nostr.h"

static void print_usage(const char* program)
{
    printf("Usage: %s <command> [options]\n", program);
    printf("\nCommands:\n");
    printf("  create <amount> <recipient_npub> <lnurl>  Create a zap request\n");
    printf("  verify <receipt_json> <request_json> <server_pubkey>  Verify a zap receipt\n");
    printf("\nOptions:\n");
    printf("  -m <message>    Add a message to the zap request\n");
    printf("  -r <relay>      Specify relay URL (can be used multiple times)\n");
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    nostr_error_t err = nostr_init();
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr: %s\n", nostr_error_string(err));
        return 1;
    }
    
    if (strcmp(argv[1], "create") == 0) {
        if (argc < 5) {
            print_usage(argv[0]);
            nostr_cleanup();
            return 1;
        }
        
        uint64_t amount = strtoull(argv[2], NULL, 10);
        const char* recipient_bech32 = argv[3];
        const char* lnurl = argv[4];
        const char* message = NULL;
        const char* relays[10] = {"wss://relay.damus.io"};
        size_t relay_count = 1;
        
        for (int i = 5; i < argc; i++) {
            if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
                message = argv[++i];
            } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
                if (relay_count < 10) {
                    relays[relay_count++] = argv[++i];
                }
            }
        }
        
        nostr_key recipient;
        err = nostr_key_from_bech32(recipient_bech32, &recipient);
        if (err != NOSTR_OK) {
            fprintf(stderr, "Invalid recipient npub: %s\n", nostr_error_string(err));
            nostr_cleanup();
            return 1;
        }
        
        nostr_event* zap_request;
        err = nostr_zap_create_request(&zap_request, amount, &recipient, lnurl, message, relays, relay_count);
        if (err != NOSTR_OK) {
            fprintf(stderr, "Failed to create zap request: %s\n", nostr_error_string(err));
            nostr_cleanup();
            return 1;
        }
        
        nostr_privkey privkey;
        nostr_key pubkey;
        err = nostr_key_generate(&privkey, &pubkey);
        if (err != NOSTR_OK) {
            fprintf(stderr, "Failed to generate key: %s\n", nostr_error_string(err));
            nostr_event_destroy(zap_request);
            nostr_cleanup();
            return 1;
        }
        
        err = nostr_event_sign(zap_request, &privkey);
        if (err != NOSTR_OK) {
            fprintf(stderr, "Failed to sign zap request: %s\n", nostr_error_string(err));
            nostr_event_destroy(zap_request);
            nostr_cleanup();
            return 1;
        }
        
        char* json;
        err = nostr_event_to_json(zap_request, &json);
        if (err != NOSTR_OK) {
            fprintf(stderr, "Failed to serialize zap request: %s\n", nostr_error_string(err));
            nostr_event_destroy(zap_request);
            nostr_cleanup();
            return 1;
        }
        
        printf("Zap Request (Kind %d):\n%s\n", zap_request->kind, json);
        
        free(json);
        nostr_event_destroy(zap_request);
        
    } else if (strcmp(argv[1], "verify") == 0) {
        if (argc < 5) {
            print_usage(argv[0]);
            nostr_cleanup();
            return 1;
        }
        
        const char* receipt_json = argv[2];
        const char* request_json = argv[3];
        const char* server_pubkey = argv[4];
        
        nostr_event* receipt;
        nostr_event* request;
        
        err = nostr_event_from_json(receipt_json, &receipt);
        if (err != NOSTR_OK) {
            fprintf(stderr, "Failed to parse receipt: %s\n", nostr_error_string(err));
            nostr_cleanup();
            return 1;
        }
        
        err = nostr_event_from_json(request_json, &request);
        if (err != NOSTR_OK) {
            fprintf(stderr, "Failed to parse request: %s\n", nostr_error_string(err));
            nostr_event_destroy(receipt);
            nostr_cleanup();
            return 1;
        }
        
        err = nostr_zap_verify(receipt, request, server_pubkey);
        if (err == NOSTR_OK) {
            printf("Success: Zap receipt is valid!\n");
            
            uint64_t amount = 0;
            char* bolt11 = NULL;
            nostr_zap_parse_receipt(receipt, &amount, &bolt11, NULL, NULL);
            
            if (amount > 0) {
                printf("Amount: %lu millisats\n", (unsigned long)amount);
            }
            if (bolt11) {
                printf("Invoice: %.50s...\n", bolt11);
                free(bolt11);
            }
        } else {
            printf("Error: Zap receipt verification failed: %s\n", nostr_error_string(err));
        }
        
        nostr_event_destroy(receipt);
        nostr_event_destroy(request);
        
    } else {
        print_usage(argv[0]);
        nostr_cleanup();
        return 1;
    }
    
    nostr_cleanup();
    return 0;
}