#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include "../include/nostr.h"

int main(int argc, char* argv[]) {
    int target_difficulty = 8;
    int use_threading = 0;
    
    if (argc > 1) {
        target_difficulty = atoi(argv[1]);
        if (target_difficulty < 1 || target_difficulty > 32) {
            printf("Usage: %s [difficulty] [threading]\n", argv[0]);
            printf("  difficulty: 1-32 (default: 8)\n");
            printf("  threading: 0 or 1 (default: 0)\n");
            return 1;
        }
    }
    
    if (argc > 2) {
        use_threading = atoi(argv[2]);
    }
    
    printf("NIP-13 Proof of Work Example\n");
    printf("Target difficulty: %d bits\n", target_difficulty);
    printf("Threading: %s\n", use_threading ? "enabled" : "disabled");
    printf("========================================\n");
    
    nostr_error_t err = nostr_init();
    if (err != NOSTR_OK) {
        printf("Failed to initialize library: %s\n", nostr_error_string(err));
        return 1;
    }
    
    nostr_keypair keypair;
    err = nostr_keypair_generate(&keypair);
    if (err != NOSTR_OK) {
        printf("Failed to generate keypair: %s\n", nostr_error_string(err));
        return 1;
    }
    
    char pubkey_hex[65];
    err = nostr_keypair_export_public_hex(&keypair, pubkey_hex, sizeof(pubkey_hex));
    if (err == NOSTR_OK) {
        printf("Public key: %s\n", pubkey_hex);
    }
    
    nostr_event* event;
    err = nostr_event_create(&event);
    if (err != NOSTR_OK) {
        printf("Failed to create event: %s\n", nostr_error_string(err));
        return 1;
    }
    
    event->kind = 1;
    event->pubkey = keypair.pubkey;
    event->created_at = time(NULL);
    err = nostr_event_set_content(event, "It's just me mining my own business");
    if (err != NOSTR_OK) {
        printf("Failed to set content: %s\n", nostr_error_string(err));
        return 1;
    }
    
    err = nostr_nip13_add_nonce_tag(event, 0, target_difficulty);
    if (err != NOSTR_OK) {
        printf("Failed to add nonce tag: %s\n", nostr_error_string(err));
        return 1;
    }
    
    printf("Mining event (this may take some time for higher difficulties)...\n");
    
    clock_t start = clock();
    if (use_threading) {
        err = nostr_nip13_mine_event_threaded(event, target_difficulty, 0, 0);
    } else {
        err = nostr_nip13_mine_event(event, target_difficulty, 0);
    }
    clock_t end = clock();
    
    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    if (err == NOSTR_OK) {
        printf("Success: Successfully mined event in %.2f seconds!\n", time_taken);
        
        err = nostr_event_compute_id(event);
        if (err == NOSTR_OK) {
            int actual_difficulty = nostr_nip13_calculate_difficulty(event->id);
            printf("Success: Achieved difficulty: %d bits\n", actual_difficulty);
            
            char event_id_hex[65];
            for (int i = 0; i < 32; i++) {
                sprintf(event_id_hex + i * 2, "%02x", event->id[i]);
            }
            event_id_hex[64] = '\0';
            printf("Success: Event ID: %s\n", event_id_hex);
            
            err = nostr_nip13_verify_pow(event, target_difficulty);
            if (err == NOSTR_OK) {
                printf("Success: Proof of work verification: PASSED\n");
            } else {
                printf("Error: Proof of work verification: FAILED\n");
            }
            
            char* json;
            err = nostr_event_to_json(event, &json);
            if (err == NOSTR_OK) {
                printf("Success: Mined event JSON:\n%s\n", json);
                free(json);
            }
        }
    } else {
        printf("Error: Mining failed: %s\n", nostr_error_string(err));
    }
    
    nostr_event_destroy(event);
    nostr_keypair_destroy(&keypair);
    nostr_cleanup();
    
    return (err == NOSTR_OK) ? 0 : 1;
}