#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "benchmark.h"
#include "nostr_features.h"

int main(void) {
    printf("libnostr-c CPU Profiling Runner\n");
    printf("===============================\n\n");
    
    if (nostr_init() != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c\n");
        return 1;
    }
    
    printf("Running focused performance tests for CPU profiling...\n");
    printf("This will run intensive operations to generate callgrind data.\n\n");
    
    printf("Testing key operations...\n");
    for (int i = 0; i < 5000; i++) {
        nostr_keypair keypair;
        nostr_keypair_generate(&keypair);
        
        char hex[65];
        nostr_keypair_export_private_hex(&keypair, hex, sizeof(hex));
        
        char bech32[100];
        nostr_key_to_bech32(&keypair.pubkey, "npub", bech32, sizeof(bech32));
        
        uint8_t shared_secret[32];
        nostr_key_ecdh(&keypair.privkey, &keypair.pubkey, shared_secret);
        
        nostr_keypair_destroy(&keypair);
    }
    
    nostr_keypair sender, recipient;
    nostr_keypair_generate(&sender);
    nostr_keypair_generate(&recipient);

#if defined(NOSTR_FEATURE_NIP44) || defined(NOSTR_FEATURE_NIP04)
    printf("Testing crypto operations...\n");
    const char* test_message = "This is a test message for crypto profiling operations.";

    for (int i = 0; i < 1000; i++) {
#ifdef NOSTR_FEATURE_NIP44
        char* nip44_ciphertext;
        if (nostr_nip44_encrypt(&sender.privkey, &recipient.pubkey,
                               test_message, strlen(test_message), &nip44_ciphertext) == NOSTR_OK) {
            char* plaintext;
            size_t plaintext_len;
            if (nostr_nip44_decrypt(&recipient.privkey, &sender.pubkey,
                                    nip44_ciphertext, &plaintext, &plaintext_len) == NOSTR_OK) {
                free(plaintext);
            }
            free(nip44_ciphertext);
        }
#endif

#ifdef NOSTR_FEATURE_NIP04
        char* nip04_ciphertext;
        if (nostr_nip04_encrypt(&sender.privkey, &recipient.pubkey,
                               test_message, &nip04_ciphertext) == NOSTR_OK) {
            char* plaintext;
            if (nostr_nip04_decrypt(&recipient.privkey, &sender.pubkey,
                                    nip04_ciphertext, &plaintext) == NOSTR_OK) {
                free(plaintext);
            }
            free(nip04_ciphertext);
        }
#endif
    }
#endif
    
    printf("Testing event operations...\n");
    for (int i = 0; i < 5000; i++) {
        nostr_event* event;
        if (nostr_event_create(&event) == NOSTR_OK) {
            event->kind = 1;
            event->created_at = time(NULL);
            event->pubkey = sender.pubkey;
            
            nostr_event_set_content(event, "This is a test event for profiling.");
            
            const char* tag_values[] = {"p", "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"};
            nostr_event_add_tag(event, tag_values, 2);
            
            nostr_event_compute_id(event);
            nostr_event_sign(event, &sender.privkey);
            nostr_event_verify(event);
            
            char* json;
            if (nostr_event_to_json(event, &json) == NOSTR_OK) {
                nostr_event* parsed_event;
                nostr_event_from_json(json, &parsed_event);
                if (parsed_event) nostr_event_destroy(parsed_event);
                free(json);
            }
            
            nostr_event_destroy(event);
        }
    }
    
#ifdef NOSTR_FEATURE_HD_KEYS
    printf("Testing HD key derivation...\n");
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = i;

    for (int i = 0; i < 1000; i++) {
        nostr_hd_key master;
        if (nostr_hd_key_from_seed(seed, sizeof(seed), &master) == NOSTR_OK) {
            nostr_hd_key derived;
            nostr_hd_key_derive_path(&master, NOSTR_HD_PATH_STANDARD, &derived);

            nostr_keypair keypair;
            nostr_hd_key_to_keypair(&derived, &keypair);
            nostr_keypair_destroy(&keypair);
        }
    }
#endif
    
    printf("Profiling complete. Check callgrind.out for detailed analysis.\n");
    
    nostr_keypair_destroy(&sender);
    nostr_keypair_destroy(&recipient);
    nostr_cleanup();
    return 0;
}