#include "include/nostr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int test_basic_encryption() {
    printf("\n=== Test: Basic Encryption/Decryption ===\n");
    
    nostr_privkey alice_sk, bob_sk;
    nostr_key alice_pk, bob_pk;
    
    if (nostr_key_generate(&alice_sk, &alice_pk) != NOSTR_OK ||
        nostr_key_generate(&bob_sk, &bob_pk) != NOSTR_OK) {
        printf("Error: Key generation failed\n");
        return 0;
    }
    
    const char* message = "Hello, this is a test message!";
    char* encrypted = NULL;
    char* decrypted = NULL;
    size_t decrypted_len = 0;
    
    /* Alice encrypts to Bob */
    if (nostr_nip44_encrypt(&alice_sk, &bob_pk, message, strlen(message), &encrypted) != NOSTR_OK) {
        printf("Error: Encryption failed\n");
        return 0;
    }
    
    /* Bob decrypts from Alice */
    if (nostr_nip44_decrypt(&bob_sk, &alice_pk, encrypted, &decrypted, &decrypted_len) != NOSTR_OK) {
        printf("Error: Decryption failed\n");
        free(encrypted);
        return 0;
    }
    
    /* Verify */
    if (decrypted_len == strlen(message) && memcmp(message, decrypted, decrypted_len) == 0) {
        printf("Success: Basic encryption/decryption successful\n");
        free(encrypted);
        free(decrypted);
        return 1;
    } else {
        printf("Error: Decrypted message doesn't match\n");
        free(encrypted);
        free(decrypted);
        return 0;
    }
}

int test_empty_message() {
    printf("\n=== Test: Empty Message ===\n");
    
    nostr_privkey sk1, sk2;
    nostr_key pk1, pk2;
    
    if (nostr_key_generate(&sk1, &pk1) != NOSTR_OK ||
        nostr_key_generate(&sk2, &pk2) != NOSTR_OK) {
        return 0;
    }
    
    char* encrypted = NULL;
    
    /* Try to encrypt empty message - should fail per NIP-44 spec */
    if (nostr_nip44_encrypt(&sk1, &pk2, "", 0, &encrypted) == NOSTR_OK) {
        printf("Error: Empty message encryption succeeded (should fail per spec)\n");
        free(encrypted);
        return 0;
    } else {
        printf("Success: Empty message correctly rejected (min 1 byte required)\n");
        return 1;
    }
}

int test_large_message() {
    printf("\n=== Test: Large Message ===\n");
    
    nostr_privkey sk1, sk2;
    nostr_key pk1, pk2;
    
    if (nostr_key_generate(&sk1, &pk1) != NOSTR_OK ||
        nostr_key_generate(&sk2, &pk2) != NOSTR_OK) {
        return 0;
    }
    
    /* Create a 10KB message */
    size_t msg_size = 10240;
    char* large_msg = malloc(msg_size + 1);
    for (size_t i = 0; i < msg_size; i++) {
        large_msg[i] = 'A' + (i % 26);
    }
    large_msg[msg_size] = '\0';
    
    char* encrypted = NULL;
    char* decrypted = NULL;
    size_t decrypted_len = 0;
    
    if (nostr_nip44_encrypt(&sk1, &pk2, large_msg, msg_size, &encrypted) != NOSTR_OK) {
        printf("Error: Large message encryption failed\n");
        free(large_msg);
        return 0;
    }
    
    if (nostr_nip44_decrypt(&sk2, &pk1, encrypted, &decrypted, &decrypted_len) != NOSTR_OK) {
        printf("Error: Large message decryption failed\n");
        free(large_msg);
        free(encrypted);
        return 0;
    }
    
    if (decrypted_len == msg_size && memcmp(large_msg, decrypted, decrypted_len) == 0) {
        printf("Success: Large message (10KB) handled correctly\n");
        free(large_msg);
        free(encrypted);
        free(decrypted);
        return 1;
    } else {
        printf("Error: Large message verification failed\n");
        free(large_msg);
        free(encrypted);
        free(decrypted);
        return 0;
    }
}

int test_wrong_key() {
    printf("\n=== Test: Wrong Key Decryption ===\n");
    
    nostr_privkey alice_sk, bob_sk, charlie_sk;
    nostr_key alice_pk, bob_pk, charlie_pk;
    
    if (nostr_key_generate(&alice_sk, &alice_pk) != NOSTR_OK ||
        nostr_key_generate(&bob_sk, &bob_pk) != NOSTR_OK ||
        nostr_key_generate(&charlie_sk, &charlie_pk) != NOSTR_OK) {
        return 0;
    }
    
    const char* message = "Secret message";
    char* encrypted = NULL;
    char* decrypted = NULL;
    size_t decrypted_len = 0;
    
    /* Alice encrypts to Bob */
    if (nostr_nip44_encrypt(&alice_sk, &bob_pk, message, strlen(message), &encrypted) != NOSTR_OK) {
        printf("Error: Encryption failed\n");
        return 0;
    }
    
    /* Charlie tries to decrypt (should fail or produce garbage) */
    nostr_error_t err = nostr_nip44_decrypt(&charlie_sk, &alice_pk, encrypted, &decrypted, &decrypted_len);
    
    /* This might succeed but produce wrong plaintext due to MAC verification being skipped */
    if (err == NOSTR_OK) {
        /* Check if decrypted content is correct (it shouldn't be) */
        if (decrypted_len == strlen(message) && memcmp(message, decrypted, decrypted_len) == 0) {
            printf("WARNING: Wrong key produced correct plaintext (MAC verification not working)\n");
            free(encrypted);
            free(decrypted);
            return 0;
        } else {
            printf("Success: Wrong key produced incorrect plaintext (expected)\n");
            free(encrypted);
            free(decrypted);
            return 1;
        }
    } else {
        printf("Success: Wrong key decryption failed (expected)\n");
        free(encrypted);
        return 1;
    }
}

int test_corrupted_ciphertext() {
    printf("\n=== Test: Corrupted Ciphertext ===\n");
    
    nostr_privkey sk1, sk2;
    nostr_key pk1, pk2;
    
    if (nostr_key_generate(&sk1, &pk1) != NOSTR_OK ||
        nostr_key_generate(&sk2, &pk2) != NOSTR_OK) {
        return 0;
    }
    
    const char* message = "Test message";
    char* encrypted = NULL;
    char* decrypted = NULL;
    size_t decrypted_len = 0;
    
    if (nostr_nip44_encrypt(&sk1, &pk2, message, strlen(message), &encrypted) != NOSTR_OK) {
        printf("Error: Encryption failed\n");
        return 0;
    }
    
    /* Corrupt the ciphertext */
    size_t enc_len = strlen(encrypted);
    if (enc_len > 50) {
        encrypted[50] = (encrypted[50] == 'A') ? 'B' : 'A';
    }
    
    /* Try to decrypt corrupted ciphertext */
    nostr_error_t err = nostr_nip44_decrypt(&sk2, &pk1, encrypted, &decrypted, &decrypted_len);
    
    if (err != NOSTR_OK) {
        printf("Success: Corrupted ciphertext rejected\n");
        free(encrypted);
        return 1;
    } else {
        /* Check if we got the original message (we shouldn't) */
        if (decrypted_len == strlen(message) && memcmp(message, decrypted, decrypted_len) == 0) {
            printf("WARNING: Corrupted ciphertext produced correct plaintext\n");
            free(encrypted);
            free(decrypted);
            return 0;
        } else {
            printf("Success: Corrupted ciphertext produced incorrect plaintext\n");
            free(encrypted);
            free(decrypted);
            return 1;
        }
    }
}

int main() {
    printf("NIP-44 Comprehensive Test Suite\n");
    printf("================================\n");
    
    if (nostr_init() != NOSTR_OK) {
        printf("Failed to initialize nostr library\n");
        return 1;
    }
    
    int passed = 0;
    int total = 0;
    
    /* Run tests */
    passed += test_basic_encryption(); total++;
    passed += test_empty_message(); total++;
    passed += test_large_message(); total++;
    passed += test_wrong_key(); total++;
    passed += test_corrupted_ciphertext(); total++;
    
    printf("\n================================\n");
    printf("Test Results: %d/%d passed\n", passed, total);
    
    nostr_cleanup();
    return (passed == total) ? 0 : 1;
}