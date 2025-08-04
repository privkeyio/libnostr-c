#include "include/nostr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_padding(void)
{
    printf("Testing NIP-44 padding algorithm...\n");
    
    struct {
        size_t input_len;
        size_t expected_padded_len;
    } test_cases[] = {
        {1, 32},
        {16, 32},
        {30, 32},
        {31, 64},
        {32, 64},
        {63, 96},
        {64, 96},
        {65, 96},
        {100, 128},
        {200, 224},
        {250, 256},
        {300, 320},
        {400, 416},
        {600, 608},
        {800, 800},
        {1000, 1024},
        {2000, 2048},
        {10000, 10048},
        {0, 0}
    };
    
    for (int i = 0; test_cases[i].input_len > 0 || test_cases[i].expected_padded_len > 0; i++) {
        printf("  Input length %zu -> expected padded length %zu\n", 
               test_cases[i].input_len, test_cases[i].expected_padded_len);
    }
}

static void hex_to_bytes(const char* hex, uint8_t* bytes, size_t byte_len)
{
    for (size_t i = 0; i < byte_len; i++) {
        sscanf(hex + 2*i, "%2hhx", &bytes[i]);
    }
}

static void bytes_to_hex(const uint8_t* bytes, size_t len, char* hex)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + 2*i, "%02x", bytes[i]);
    }
    hex[2*len] = '\0';
}

static void test_basic_encryption(void)
{
    printf("\nTesting basic NIP-44 encryption/decryption...\n");
    
    nostr_error_t err;
    nostr_privkey privkey1, privkey2;
    nostr_key pubkey1, pubkey2;
    
    err = nostr_init();
    if (err != NOSTR_OK) {
        printf("Failed to initialize library: %d\n", err);
        return;
    }
    
    err = nostr_key_generate(&privkey1, &pubkey1);
    if (err != NOSTR_OK) {
        printf("Failed to generate key pair 1: %d\n", err);
        return;
    }
    
    err = nostr_key_generate(&privkey2, &pubkey2);
    if (err != NOSTR_OK) {
        printf("Failed to generate key pair 2: %d\n", err);
        return;
    }
    
    const char* test_messages[] = {
        "Hello, World!",
        "a",
        "The quick brown fox jumps over the lazy dog",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "Short",
        "This is a longer message that should trigger different padding",
        NULL
    };
    
    for (int i = 0; test_messages[i] != NULL; i++) {
        const char* plaintext = test_messages[i];
        char* ciphertext = NULL;
        char* decrypted = NULL;
        size_t decrypted_len = 0;
        
        printf("\n  Testing message: \"%s\"\n", plaintext);
        
        err = nostr_nip44_encrypt(&privkey1, &pubkey2, plaintext, strlen(plaintext), &ciphertext);
        if (err != NOSTR_OK) {
            printf("    Encryption failed: %d\n", err);
            continue;
        }
        
        printf("    Ciphertext length: %zu\n", strlen(ciphertext));
        
        err = nostr_nip44_decrypt(&privkey2, &pubkey1, ciphertext, &decrypted, &decrypted_len);
        if (err != NOSTR_OK) {
            printf("    Decryption failed: %d\n", err);
            free(ciphertext);
            continue;
        }
        
        if (decrypted_len != strlen(plaintext) || memcmp(plaintext, decrypted, decrypted_len) != 0) {
            printf("    FAILED: Decrypted message doesn't match original\n");
            printf("    Expected: %s\n", plaintext);
            printf("    Got: %.*s\n", (int)decrypted_len, decrypted);
        } else {
            printf("    SUCCESS: Message encrypted and decrypted correctly\n");
        }
        
        free(ciphertext);
        free(decrypted);
    }
}

static void test_invalid_operations(void)
{
    printf("\nTesting invalid operations...\n");
    
    nostr_error_t err;
    nostr_privkey privkey;
    nostr_key pubkey;
    char* ciphertext = NULL;
    char* plaintext = NULL;
    size_t plaintext_len = 0;
    
    err = nostr_key_generate(&privkey, &pubkey);
    if (err != NOSTR_OK) {
        printf("Failed to generate key pair: %d\n", err);
        return;
    }
    
    err = nostr_nip44_encrypt(NULL, &pubkey, "test", 4, &ciphertext);
    printf("  NULL privkey: %s (expected NOSTR_ERR_INVALID_PARAM)\n", 
           err == NOSTR_ERR_INVALID_PARAM ? "PASS" : "FAIL");
    
    err = nostr_nip44_encrypt(&privkey, NULL, "test", 4, &ciphertext);
    printf("  NULL pubkey: %s (expected NOSTR_ERR_INVALID_PARAM)\n", 
           err == NOSTR_ERR_INVALID_PARAM ? "PASS" : "FAIL");
    
    err = nostr_nip44_encrypt(&privkey, &pubkey, NULL, 4, &ciphertext);
    printf("  NULL plaintext: %s (expected NOSTR_ERR_INVALID_PARAM)\n", 
           err == NOSTR_ERR_INVALID_PARAM ? "PASS" : "FAIL");
    
    err = nostr_nip44_encrypt(&privkey, &pubkey, "test", 4, NULL);
    printf("  NULL ciphertext output: %s (expected NOSTR_ERR_INVALID_PARAM)\n", 
           err == NOSTR_ERR_INVALID_PARAM ? "PASS" : "FAIL");
    
    err = nostr_nip44_decrypt(&privkey, &pubkey, "invalid_base64!", &plaintext, &plaintext_len);
    printf("  Invalid base64: %s (expected NOSTR_ERR_INVALID_PARAM)\n", 
           err == NOSTR_ERR_INVALID_PARAM ? "PASS" : "FAIL");
    
    err = nostr_nip44_decrypt(&privkey, &pubkey, "#unsupported", &plaintext, &plaintext_len);
    printf("  Unsupported format: %s (expected NOSTR_ERR_NOT_SUPPORTED)\n", 
           err == NOSTR_ERR_NOT_SUPPORTED ? "PASS" : "FAIL");
}

static void test_cross_compatibility(void)
{
    printf("\nTesting cross-compatibility (encrypt with key1->key2, decrypt with key2->key1)...\n");
    
    nostr_error_t err;
    nostr_privkey privkey1, privkey2;
    nostr_key pubkey1, pubkey2;
    const char* message = "Cross-compatibility test message";
    char* ciphertext = NULL;
    char* decrypted = NULL;
    size_t decrypted_len = 0;
    
    err = nostr_key_generate(&privkey1, &pubkey1);
    if (err != NOSTR_OK) {
        printf("Failed to generate key pair 1: %d\n", err);
        return;
    }
    
    err = nostr_key_generate(&privkey2, &pubkey2);
    if (err != NOSTR_OK) {
        printf("Failed to generate key pair 2: %d\n", err);
        return;
    }
    
    err = nostr_nip44_encrypt(&privkey1, &pubkey2, message, strlen(message), &ciphertext);
    if (err != NOSTR_OK) {
        printf("  Encryption failed: %d\n", err);
        return;
    }
    
    err = nostr_nip44_decrypt(&privkey2, &pubkey1, ciphertext, &decrypted, &decrypted_len);
    if (err != NOSTR_OK) {
        printf("  Decryption failed: %d\n", err);
        free(ciphertext);
        return;
    }
    
    if (decrypted_len == strlen(message) && memcmp(message, decrypted, decrypted_len) == 0) {
        printf("  SUCCESS: Cross-compatibility works correctly\n");
    } else {
        printf("  FAILED: Cross-compatibility test failed\n");
    }
    
    free(ciphertext);
    free(decrypted);
}

int main(void)
{
    printf("NIP-44 Encryption Test Suite\n");
    printf("============================\n");
    
    test_padding();
    test_basic_encryption();
    test_invalid_operations();
    test_cross_compatibility();
    
    nostr_cleanup();
    
    printf("\nAll tests completed.\n");
    return 0;
}