#include "include/nostr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("Simple NIP-44 Test\n");
    printf("==================\n");
    
    nostr_error_t err = nostr_init();
    if (err != NOSTR_OK) {
        printf("Failed to init: %d\n", err);
        return 1;
    }
    
    /* Generate two key pairs */
    nostr_privkey alice_sk, bob_sk;
    nostr_key alice_pk, bob_pk;
    
    err = nostr_key_generate(&alice_sk, &alice_pk);
    if (err != NOSTR_OK) {
        printf("Failed to generate Alice's keys: %d\n", err);
        return 1;
    }
    
    err = nostr_key_generate(&bob_sk, &bob_pk);
    if (err != NOSTR_OK) {
        printf("Failed to generate Bob's keys: %d\n", err);
        return 1;
    }
    
    /* Alice encrypts a message to Bob */
    const char* message = "Hello Bob!";
    char* encrypted = NULL;
    
    printf("\nAlice encrypting to Bob: \"%s\"\n", message);
    err = nostr_nip44_encrypt(&alice_sk, &bob_pk, message, strlen(message), &encrypted);
    if (err != NOSTR_OK) {
        printf("Encryption failed: %d\n", err);
        return 1;
    }
    
    printf("Encrypted (base64): %.50s...\n", encrypted);
    printf("Ciphertext length: %zu\n", strlen(encrypted));
    
    /* Bob decrypts the message from Alice */
    char* decrypted = NULL;
    size_t decrypted_len = 0;
    
    printf("\nBob decrypting from Alice...\n");
    err = nostr_nip44_decrypt(&bob_sk, &alice_pk, encrypted, &decrypted, &decrypted_len);
    if (err != NOSTR_OK) {
        printf("Decryption failed: %d\n", err);
        
        /* Additional debugging */
        if (err == NOSTR_ERR_INVALID_SIGNATURE) {
            printf("  -> MAC verification failed\n");
        } else if (err == NOSTR_ERR_INVALID_PARAM) {
            printf("  -> Invalid parameter (possibly padding issue)\n");
        }
        
        free(encrypted);
        return 1;
    }
    
    printf("Decrypted: \"%.*s\"\n", (int)decrypted_len, decrypted);
    printf("Length: %zu\n", decrypted_len);
    
    /* Verify it matches */
    if (decrypted_len == strlen(message) && memcmp(message, decrypted, decrypted_len) == 0) {
        printf("\nSUCCESS! Message correctly encrypted and decrypted.\n");
    } else {
        printf("\nFAILURE! Decrypted message doesn't match original.\n");
    }
    
    free(encrypted);
    free(decrypted);
    
    nostr_cleanup();
    return 0;
}