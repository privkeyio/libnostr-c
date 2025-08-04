#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "nostr.h"

static void hex_to_bytes(const char* hex, uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + i * 2, "%2hhx", &bytes[i]);
    }
}

static void bytes_to_hex(const uint8_t* bytes, size_t len, char* hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

static void test_master_key_generation() {
    printf("Testing master key generation from seed...\n");
    
    const char* seed_hex = "000102030405060708090a0b0c0d0e0f";
    uint8_t seed[16];
    hex_to_bytes(seed_hex, seed, 16);
    
    nostr_hd_key master;
    nostr_error_t err = nostr_hd_key_from_seed(seed, 16, &master);
    assert(err == NOSTR_OK);
    
    char privkey_hex[65];
    bytes_to_hex(master.privkey.data, 32, privkey_hex);
    printf("Master private key: %s\n", privkey_hex);
    
    char chaincode_hex[65];
    bytes_to_hex(master.chain_code, 32, chaincode_hex);
    printf("Master chain code: %s\n", chaincode_hex);
    
    char pubkey_hex[65];
    bytes_to_hex(master.pubkey.data, 32, pubkey_hex);
    printf("Master public key: %s\n", pubkey_hex);
    
    printf("Success: Master key generation successful\n\n");
}

static void test_hardened_derivation() {
    printf("Testing hardened key derivation...\n");
    
    const char* seed_hex = "000102030405060708090a0b0c0d0e0f";
    uint8_t seed[16];
    hex_to_bytes(seed_hex, seed, 16);
    
    nostr_hd_key master;
    nostr_error_t err = nostr_hd_key_from_seed(seed, 16, &master);
    assert(err == NOSTR_OK);
    
    nostr_hd_key child;
    err = nostr_hd_key_derive(&master, 0x80000000, &child);
    assert(err == NOSTR_OK);
    
    char privkey_hex[65];
    bytes_to_hex(child.privkey.data, 32, privkey_hex);
    printf("m/0' private key: %s\n", privkey_hex);
    
    char chaincode_hex[65];
    bytes_to_hex(child.chain_code, 32, chaincode_hex);
    printf("m/0' chain code: %s\n", chaincode_hex);
    
    printf("Success: Hardened derivation successful\n\n");
}

static void test_non_hardened_derivation() {
    printf("Testing non-hardened key derivation...\n");
    
    const char* seed_hex = "000102030405060708090a0b0c0d0e0f";
    uint8_t seed[16];
    hex_to_bytes(seed_hex, seed, 16);
    
    nostr_hd_key master;
    nostr_error_t err = nostr_hd_key_from_seed(seed, 16, &master);
    assert(err == NOSTR_OK);
    
    nostr_hd_key hardened;
    err = nostr_hd_key_derive(&master, 0x80000000, &hardened);
    assert(err == NOSTR_OK);
    
    nostr_hd_key child;
    err = nostr_hd_key_derive(&hardened, 1, &child);
    assert(err == NOSTR_OK);
    
    char privkey_hex[65];
    bytes_to_hex(child.privkey.data, 32, privkey_hex);
    printf("m/0'/1 private key: %s\n", privkey_hex);
    
    printf("Success: Non-hardened derivation successful\n\n");
}

static void test_path_derivation() {
    printf("Testing path-based key derivation...\n");
    
    const char* seed_hex = "000102030405060708090a0b0c0d0e0f";
    uint8_t seed[16];
    hex_to_bytes(seed_hex, seed, 16);
    
    nostr_hd_key master;
    nostr_error_t err = nostr_hd_key_from_seed(seed, 16, &master);
    assert(err == NOSTR_OK);
    
    nostr_hd_key derived;
    err = nostr_hd_key_derive_path(&master, "m/44'/1237'/0'/0/0", &derived);
    assert(err == NOSTR_OK);
    
    char privkey_hex[65];
    bytes_to_hex(derived.privkey.data, 32, privkey_hex);
    printf("Standard Nostr path private key: %s\n", privkey_hex);
    
    char pubkey_hex[65];
    bytes_to_hex(derived.pubkey.data, 32, pubkey_hex);
    printf("Standard Nostr path public key: %s\n", pubkey_hex);
    
    nostr_keypair keypair;
    err = nostr_hd_key_to_keypair(&derived, &keypair);
    assert(err == NOSTR_OK);
    assert(keypair.initialized == 1);
    assert(memcmp(keypair.privkey.data, derived.privkey.data, 32) == 0);
    assert(memcmp(keypair.pubkey.data, derived.pubkey.data, 32) == 0);
    
    printf("Success: Path derivation successful\n\n");
}

static void test_bip32_compatible_derivation() {
    printf("Testing BIP-32 compatible key derivation...\n");
    
    const char* seed_hex = "000102030405060708090a0b0c0d0e0f";
    uint8_t seed[16];
    hex_to_bytes(seed_hex, seed, 16);
    
    nostr_hd_key master;
    nostr_error_t err = nostr_hd_key_from_seed(seed, 16, &master);
    assert(err == NOSTR_OK);
    
    const char* expected_master_chain = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
    
    char chaincode_hex[65];
    bytes_to_hex(master.chain_code, 32, chaincode_hex);
    
    printf("Master chain code matches BIP-32: %s\n", 
           strcmp(chaincode_hex, expected_master_chain) == 0 ? "YES" : "NO");
    assert(strcmp(chaincode_hex, expected_master_chain) == 0);
    
    nostr_hd_key child1, child2, child3;
    
    err = nostr_hd_key_derive(&master, 0x80000000, &child1);
    assert(err == NOSTR_OK);
    
    err = nostr_hd_key_derive(&child1, 1, &child2);
    assert(err == NOSTR_OK);
    
    err = nostr_hd_key_derive(&child2, 0x80000002, &child3);
    assert(err == NOSTR_OK);
    
    char privkey_hex[65];
    bytes_to_hex(child3.privkey.data, 32, privkey_hex);
    printf("m/0'/1/2' private key: %s\n", privkey_hex);
    
    bytes_to_hex(child3.chain_code, 32, chaincode_hex);
    printf("m/0'/1/2' chain code: %s\n", chaincode_hex);
    
    printf("Success: BIP-32 compatible derivation successful\n");
    printf("  (Note: Public keys are x-only for Nostr compatibility)\n\n");
}

static void test_error_cases() {
    printf("Testing error cases...\n");
    
    nostr_hd_key master, child;
    
    nostr_error_t err = nostr_hd_key_from_seed(NULL, 16, &master);
    assert(err == NOSTR_ERR_INVALID_PARAM);
    
    uint8_t seed[16] = {0};
    err = nostr_hd_key_from_seed(seed, 0, &master);
    assert(err == NOSTR_ERR_INVALID_PARAM);
    
    err = nostr_hd_key_from_seed(seed, 16, NULL);
    assert(err == NOSTR_ERR_INVALID_PARAM);
    
    err = nostr_hd_key_derive(NULL, 0, &child);
    assert(err == NOSTR_ERR_INVALID_PARAM);
    
    err = nostr_hd_key_derive(&master, 0, NULL);
    assert(err == NOSTR_ERR_INVALID_PARAM);
    
    err = nostr_hd_key_derive_path(&master, "invalid/path", &child);
    assert(err == NOSTR_ERR_INVALID_PARAM);
    
    err = nostr_hd_key_derive_path(&master, "n/0/1", &child);
    assert(err == NOSTR_ERR_INVALID_PARAM);
    
    printf("Success: Error handling works correctly\n\n");
}

int main() {
    printf("=== HD Key Derivation Tests ===\n\n");
    
    nostr_error_t err = nostr_init();
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c: %d\n", err);
        return 1;
    }
    
    test_master_key_generation();
    test_hardened_derivation();
    test_non_hardened_derivation();
    test_path_derivation();
    test_bip32_compatible_derivation();
    test_error_cases();
    
    printf("Success: All HD key derivation tests passed!\n");
    
    nostr_cleanup();
    return 0;
}