#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "nostr.h"

int main() {
    printf("HD Key Derivation Example\n");
    printf("========================\n\n");
    
    nostr_error_t err = nostr_init();
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c: %d\n", err);
        return 1;
    }
    
    const char* seed_phrase = "example seed for HD key generation";
    nostr_hd_key master;
    
    err = nostr_hd_key_from_seed((const uint8_t*)seed_phrase, strlen(seed_phrase), &master);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to generate master key: %d\n", err);
        return 1;
    }
    
    char hex[65];
    
    nostr_key_to_hex(&master.pubkey, hex, sizeof(hex));
    printf("Master public key: %s\n", hex);
    
    printf("\nDeriving standard Nostr key (m/44'/1237'/0'/0/0)...\n");
    nostr_hd_key nostr_key;
    err = nostr_hd_key_derive_path(&master, NOSTR_HD_PATH_STANDARD, &nostr_key);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to derive Nostr key: %d\n", err);
        return 1;
    }
    
    nostr_key_to_hex(&nostr_key.pubkey, hex, sizeof(hex));
    printf("Nostr public key: %s\n", hex);
    
    char bech32[256];
    err = nostr_key_to_bech32(&nostr_key.pubkey, "npub", bech32, sizeof(bech32));
    if (err == NOSTR_OK) {
        printf("Nostr npub: %s\n", bech32);
    }
    
    printf("\nDeriving multiple accounts...\n");
    for (int i = 0; i < 3; i++) {
        char path[64];
        snprintf(path, sizeof(path), "m/44'/1237'/%d'/0/0", i);
        
        nostr_hd_key account_key;
        err = nostr_hd_key_derive_path(&master, path, &account_key);
        if (err != NOSTR_OK) {
            fprintf(stderr, "Failed to derive account %d: %d\n", i, err);
            continue;
        }
        
        nostr_key_to_hex(&account_key.pubkey, hex, sizeof(hex));
        printf("Account %d public key: %s\n", i, hex);
    }
    
    printf("\nConverting to keypair for event signing...\n");
    nostr_keypair keypair;
    err = nostr_hd_key_to_keypair(&nostr_key, &keypair);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to convert to keypair: %d\n", err);
        return 1;
    }
    
    printf("Successfully created keypair from HD key\n");
    
    nostr_privkey_to_hex(&keypair.privkey, hex, sizeof(hex));
    printf("Private key (hex): %s\n", hex);
    
    err = nostr_privkey_to_bech32(&keypair.privkey, bech32, sizeof(bech32));
    if (err == NOSTR_OK) {
        printf("Private key (nsec): %s\n", bech32);
    }
    nostr_cleanup();
    
    return 0;
}