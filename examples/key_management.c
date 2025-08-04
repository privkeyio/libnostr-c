#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nostr.h"

void demonstrate_key_generation() {
    printf("Key Generation Example\n");
    printf("======================\n\n");
    
    nostr_privkey privkey;
    nostr_key pubkey;
    
    if (nostr_key_generate(&privkey, &pubkey) != NOSTR_OK) {
        fprintf(stderr, "Failed to generate keypair\n");
        return;
    }
    
    char privkey_hex[65], pubkey_hex[65];
    char nsec[100], npub[100];
    
    nostr_privkey_to_hex(&privkey, privkey_hex, sizeof(privkey_hex));
    nostr_key_to_hex(&pubkey, pubkey_hex, sizeof(pubkey_hex));
    
    nostr_privkey_to_bech32(&privkey, nsec, sizeof(nsec));
    nostr_key_to_bech32(&pubkey, "npub", npub, sizeof(npub));
    
    printf("Generated keypair:\n");
    printf("  Private key (hex): %s\n", privkey_hex);
    printf("  Public key (hex):  %s\n", pubkey_hex);
    printf("  Private key (nsec): %s\n", nsec);
    printf("  Public key (npub):  %s\n\n", npub);
}

void demonstrate_key_conversion() {
    printf("Key Format Conversion Example\n");
    printf("=============================\n\n");
    
    const char* test_nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    const char* test_npub = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";
    
    nostr_privkey privkey;
    nostr_key pubkey;
    
    printf("Converting from bech32 formats:\n");
    printf("  Input nsec: %s\n", test_nsec);
    printf("  Input npub: %s\n\n", test_npub);
    
    if (nostr_privkey_from_bech32(test_nsec, &privkey) == NOSTR_OK) {
        char privkey_hex[65];
        nostr_privkey_to_hex(&privkey, privkey_hex, sizeof(privkey_hex));
        printf("  Converted private key (hex): %s\n", privkey_hex);
    }
    
    if (nostr_key_from_bech32(test_npub, &pubkey) == NOSTR_OK) {
        char pubkey_hex[65];
        nostr_key_to_hex(&pubkey, pubkey_hex, sizeof(pubkey_hex));
        printf("  Converted public key (hex):  %s\n", pubkey_hex);
    }
    
    const char* test_hex_privkey = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
    const char* test_hex_pubkey = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
    
    printf("\nConverting from hex formats:\n");
    printf("  Input private key (hex): %s\n", test_hex_privkey);
    printf("  Input public key (hex):  %s\n\n", test_hex_pubkey);
    
    if (nostr_privkey_from_hex(test_hex_privkey, &privkey) == NOSTR_OK) {
        char nsec[100];
        nostr_privkey_to_bech32(&privkey, nsec, sizeof(nsec));
        printf("  Converted private key (nsec): %s\n", nsec);
    }
    
    if (nostr_key_from_hex(test_hex_pubkey, &pubkey) == NOSTR_OK) {
        char npub[100];
        nostr_key_to_bech32(&pubkey, "npub", npub, sizeof(npub));
        printf("  Converted public key (npub):  %s\n", npub);
    }
    
    printf("\n");
}

void demonstrate_event_id_conversion() {
    printf("Event ID Conversion Example\n");
    printf("===========================\n\n");
    
    uint8_t test_event_id[32] = {
        0x5c, 0x83, 0xda, 0x77, 0xaf, 0x1d, 0xec, 0x6d,
        0x72, 0x89, 0x83, 0x49, 0x98, 0xad, 0x7a, 0xaf,
        0xbd, 0x9e, 0x21, 0x91, 0x39, 0x6d, 0x75, 0xec,
        0x3c, 0xc2, 0x7f, 0x5a, 0x77, 0x22, 0x6f, 0x36
    };
    
    char event_id_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&event_id_hex[i * 2], "%02x", test_event_id[i]);
    }
    event_id_hex[64] = '\0';
    
    printf("Event ID (hex): %s\n", event_id_hex);
    
    char note_bech32[100];
    if (nostr_event_id_to_bech32(test_event_id, note_bech32, sizeof(note_bech32)) == NOSTR_OK) {
        printf("Event ID (note): %s\n", note_bech32);
        
        uint8_t converted_back[32];
        if (nostr_event_id_from_bech32(note_bech32, converted_back) == NOSTR_OK) {
            printf("Conversion successful: ");
            if (memcmp(test_event_id, converted_back, 32) == 0) {
                printf("Success: Round-trip conversion matches\n");
            } else {
                printf("Error: Round-trip conversion failed\n");
            }
        }
    }
    
    printf("\n");
}

int main(void) {
    printf("libnostr-c Key Management Examples\n");
    printf("===================================\n\n");
    
    if (nostr_init() != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c\n");
        return 1;
    }
    
    demonstrate_key_generation();
    demonstrate_key_conversion();
    demonstrate_event_id_conversion();
    
    nostr_cleanup();
    
    printf("Success: All key management examples completed successfully!\n");
    return 0;
}