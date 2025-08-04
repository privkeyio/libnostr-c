#include "../include/nostr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int test_count = 0;
static int test_passed = 0;

#define TEST_ASSERT(condition, message) do { \
    test_count++; \
    if (condition) { \
        test_passed++; \
        printf("Success: Test %d passed: %s\n", test_count, message); \
    } else { \
        printf("Error: Test %d failed: %s\n", test_count, message); \
    } \
} while(0)

static void test_nip04_basic_encryption()
{
    printf("\n=== Testing NIP-04 Basic Encryption ===\n");
    
    nostr_keypair sender, recipient;
    TEST_ASSERT(nostr_keypair_generate(&sender) == NOSTR_OK, "Generate sender keypair");
    TEST_ASSERT(nostr_keypair_generate(&recipient) == NOSTR_OK, "Generate recipient keypair");
    
    const char* message = "Hello, NIP-04!";
    char* encrypted = NULL;
    char* decrypted = NULL;
    
    nostr_error_t result = nostr_nip04_encrypt(&sender.privkey, &recipient.pubkey, message, &encrypted);
    
    if (result == NOSTR_ERR_NOT_SUPPORTED) {
        printf("  Success: NIP-04 not supported (compiled without noscrypt)\n");
        nostr_keypair_destroy(&sender);
        nostr_keypair_destroy(&recipient);
        return;
    }
    
    TEST_ASSERT(result == NOSTR_OK, "Encryption succeeds");
    TEST_ASSERT(encrypted != NULL, "Encrypted output not null");
    
    if (encrypted) {
        TEST_ASSERT(strstr(encrypted, "?iv=") != NULL, "Encrypted format contains ?iv= separator");
        
        result = nostr_nip04_decrypt(&recipient.privkey, &sender.pubkey, encrypted, &decrypted);
        TEST_ASSERT(result == NOSTR_OK, "Decryption succeeds");
        TEST_ASSERT(decrypted != NULL, "Decrypted output not null");
        
        if (decrypted) {
            TEST_ASSERT(strcmp(message, decrypted) == 0, "Decrypted message matches original");
            free(decrypted);
        }
        
        free(encrypted);
    }
    
    nostr_keypair_destroy(&sender);
    nostr_keypair_destroy(&recipient);
}

static void test_nip04_message_format()
{
    printf("\n=== Testing NIP-04 Message Format ===\n");
    
    nostr_keypair sender, recipient;
    nostr_keypair_generate(&sender);
    nostr_keypair_generate(&recipient);
    
    const char* message = "Format test";
    char* encrypted = NULL;
    
    nostr_error_t result = nostr_nip04_encrypt(&sender.privkey, &recipient.pubkey, message, &encrypted);
    
    if (result == NOSTR_ERR_NOT_SUPPORTED) {
        printf("  Success: NIP-04 not supported (compiled without noscrypt)\n");
        nostr_keypair_destroy(&sender);
        nostr_keypair_destroy(&recipient);
        return;
    }
    
    if (encrypted) {
        char* iv_start = strstr(encrypted, "?iv=");
        TEST_ASSERT(iv_start != NULL, "IV separator found");
        
        if (iv_start) {
            size_t content_len = iv_start - encrypted;
            size_t iv_len = strlen(iv_start + 4);
            
            TEST_ASSERT(content_len > 0, "Content part has length");
            TEST_ASSERT(iv_len == 24, "IV part has correct base64 length (16 bytes -> 24 chars)");
        }
        
        free(encrypted);
    }
    
    nostr_keypair_destroy(&sender);
    nostr_keypair_destroy(&recipient);
}

static void test_nip04_edge_cases()
{
    printf("\n=== Testing NIP-04 Edge Cases ===\n");
    
    nostr_keypair sender, recipient;
    nostr_keypair_generate(&sender);
    nostr_keypair_generate(&recipient);
    
    char* encrypted = NULL;
    char* decrypted = NULL;
    
    // Test empty message
    nostr_error_t result = nostr_nip04_encrypt(&sender.privkey, &recipient.pubkey, "", &encrypted);
    
    if (result == NOSTR_ERR_NOT_SUPPORTED) {
        printf("  Success: NIP-04 not supported (compiled without noscrypt)\n");
        nostr_keypair_destroy(&sender);
        nostr_keypair_destroy(&recipient);
        return;
    }
    if (result == NOSTR_OK) {
        result = nostr_nip04_decrypt(&recipient.privkey, &sender.pubkey, encrypted, &decrypted);
        if (result == NOSTR_OK && decrypted) {
            TEST_ASSERT(strcmp("", decrypted) == 0, "Empty message round-trip");
            free(decrypted);
        }
        free(encrypted);
    }
    
    // Test long message
    char long_message[1000];
    memset(long_message, 'A', 999);
    long_message[999] = '\0';
    
    encrypted = NULL;
    decrypted = NULL;
    result = nostr_nip04_encrypt(&sender.privkey, &recipient.pubkey, long_message, &encrypted);
    TEST_ASSERT(result == NOSTR_OK, "Long message encryption");
    
    if (result == NOSTR_OK && encrypted) {
        result = nostr_nip04_decrypt(&recipient.privkey, &sender.pubkey, encrypted, &decrypted);
        TEST_ASSERT(result == NOSTR_OK, "Long message decryption");
        
        if (decrypted) {
            TEST_ASSERT(strcmp(long_message, decrypted) == 0, "Long message round-trip");
            free(decrypted);
        }
        free(encrypted);
    }
    
    // Test invalid parameters
    result = nostr_nip04_encrypt(NULL, &recipient.pubkey, "test", &encrypted);
    TEST_ASSERT(result == NOSTR_ERR_INVALID_PARAM, "Null sender private key rejected");
    
    result = nostr_nip04_encrypt(&sender.privkey, NULL, "test", &encrypted);
    TEST_ASSERT(result == NOSTR_ERR_INVALID_PARAM, "Null recipient public key rejected");
    
    result = nostr_nip04_decrypt(&recipient.privkey, &sender.pubkey, "invalid", &decrypted);
    TEST_ASSERT(result == NOSTR_ERR_INVALID_PARAM, "Invalid ciphertext rejected");
    
    nostr_keypair_destroy(&sender);
    nostr_keypair_destroy(&recipient);
}

static void test_nip04_interoperability()
{
    printf("\n=== Testing NIP-04 Interoperability ===\n");
    
    // Test with known test vectors if available
    // This would be expanded with actual test vectors from other implementations
    
    nostr_keypair sender, recipient;
    nostr_keypair_generate(&sender);
    nostr_keypair_generate(&recipient);
    
    const char* test_message = "NIP-04 test vector";
    char* encrypted1 = NULL;
    char* encrypted2 = NULL;
    char* decrypted1 = NULL;
    char* decrypted2 = NULL;
    
    // Encrypt the same message twice - should produce different results (due to random IV)
    nostr_error_t result1 = nostr_nip04_encrypt(&sender.privkey, &recipient.pubkey, test_message, &encrypted1);
    
    if (result1 == NOSTR_ERR_NOT_SUPPORTED) {
        printf("  Success: NIP-04 not supported (compiled without noscrypt)\n");
        nostr_keypair_destroy(&sender);
        nostr_keypair_destroy(&recipient);
        return;
    }
    
    nostr_nip04_encrypt(&sender.privkey, &recipient.pubkey, test_message, &encrypted2);
    
    if (encrypted1 && encrypted2) {
        TEST_ASSERT(strcmp(encrypted1, encrypted2) != 0, "Same message produces different ciphertexts (random IV)");
        
        // Both should decrypt to the same plaintext
        nostr_nip04_decrypt(&recipient.privkey, &sender.pubkey, encrypted1, &decrypted1);
        nostr_nip04_decrypt(&recipient.privkey, &sender.pubkey, encrypted2, &decrypted2);
        
        if (decrypted1 && decrypted2) {
            TEST_ASSERT(strcmp(decrypted1, test_message) == 0, "First encryption decrypts correctly");
            TEST_ASSERT(strcmp(decrypted2, test_message) == 0, "Second encryption decrypts correctly");
            TEST_ASSERT(strcmp(decrypted1, decrypted2) == 0, "Both decrypt to same plaintext");
            
            free(decrypted1);
            free(decrypted2);
        }
        
        free(encrypted1);
        free(encrypted2);
    }
    
    nostr_keypair_destroy(&sender);
    nostr_keypair_destroy(&recipient);
}

int main()
{
    printf("NIP-04 Legacy Encryption Test Suite\n");
    printf("====================================\n");
    
    if (nostr_init() != NOSTR_OK) {
        printf("Failed to initialize nostr library\n");
        return 1;
    }
    
    test_nip04_basic_encryption();
    test_nip04_message_format();
    test_nip04_edge_cases();
    test_nip04_interoperability();
    
    printf("\n=== Test Summary ===\n");
    printf("Tests run: %d\n", test_count);
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_count - test_passed);
    
    if (test_passed == test_count) {
        printf("Success: All NIP-04 tests passed!\n");
        return 0;
    } else {
        printf("Error: Some tests failed!\n");
        return 1;
    }
}