#include "nostr.h"

#ifdef NOSTR_FEATURE_HD_KEYS

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <arpa/inet.h>

#include "data/bip39_english.h"

extern void secure_wipe(void* data, size_t len);
extern int nostr_random_bytes(uint8_t* buf, size_t len);

#ifdef HAVE_NOSCRYPT
#include <noscrypt.h>
extern NCContext* nc_ctx;
#else
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
extern secp256k1_context* secp256k1_ctx;
#endif

#define HD_HARDENED_FLAG 0x80000000
#define BIP32_KEY_SIZE 32
#define BIP32_CHAINCODE_SIZE 32

static const char HD_SEED_KEY[] = "Bitcoin seed";

nostr_error_t nostr_hd_key_from_seed(const uint8_t* seed, size_t seed_len, nostr_hd_key* master)
{
    unsigned char hash[64];
    unsigned int hash_len = 64;
    
    if (!seed || seed_len < 16 || seed_len > 64 || !master) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    memset(master, 0, sizeof(nostr_hd_key));
    
    if (!HMAC(EVP_sha512(), HD_SEED_KEY, strlen(HD_SEED_KEY), seed, seed_len, hash, &hash_len)) {
        return NOSTR_ERR_MEMORY;
    }
    
    memcpy(master->privkey.data, hash, 32);
    memcpy(master->chain_code, hash + 32, 32);
    
#ifdef HAVE_NOSCRYPT
    NCSecretKey nc_seckey;
    NCPublicKey nc_pubkey;
    
    memcpy(nc_seckey.key, master->privkey.data, 32);
    
    if (NCGetPublicKey(nc_ctx, &nc_seckey, &nc_pubkey) != NC_SUCCESS) {
        secure_wipe(hash, 64);
        secure_wipe(master, sizeof(nostr_hd_key));
        return NOSTR_ERR_INVALID_KEY;
    }
    
    memcpy(master->pubkey.data, nc_pubkey.key, 32);
    
    secure_wipe(&nc_seckey, sizeof(nc_seckey));
#else
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey xonly_pubkey;
    
    if (!secp256k1_keypair_create(secp256k1_ctx, &keypair, master->privkey.data)) {
        secure_wipe(hash, 64);
        secure_wipe(master, sizeof(nostr_hd_key));
        return NOSTR_ERR_INVALID_KEY;
    }
    
    if (!secp256k1_keypair_xonly_pub(secp256k1_ctx, &xonly_pubkey, NULL, &keypair)) {
        secure_wipe(hash, 64);
        secure_wipe(master, sizeof(nostr_hd_key));
        secure_wipe(&keypair, sizeof(keypair));
        return NOSTR_ERR_INVALID_KEY;
    }
    
    if (!secp256k1_xonly_pubkey_serialize(secp256k1_ctx, master->pubkey.data, &xonly_pubkey)) {
        secure_wipe(hash, 64);
        secure_wipe(master, sizeof(nostr_hd_key));
        secure_wipe(&keypair, sizeof(keypair));
        return NOSTR_ERR_INVALID_KEY;
    }
    
    secure_wipe(&keypair, sizeof(keypair));
#endif
    
    secure_wipe(hash, 64);
    return NOSTR_OK;
}

nostr_error_t nostr_hd_key_derive(const nostr_hd_key* parent, uint32_t index, nostr_hd_key* child)
{
    unsigned char hash[64];
    unsigned int hash_len = 64;
    unsigned char data[37];
    uint32_t index_be = htonl(index);
    
    if (!parent || !child) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    memset(child, 0, sizeof(nostr_hd_key));
    
    if (index & HD_HARDENED_FLAG) {
        data[0] = 0x00;
        memcpy(data + 1, parent->privkey.data, 32);
        memcpy(data + 33, &index_be, 4);
    } else {
#ifdef HAVE_NOSCRYPT
        NCPublicKey nc_pubkey;
        memcpy(nc_pubkey.key, parent->pubkey.data, 32);

        data[0] = 0x02;
        memcpy(data + 1, parent->pubkey.data, 32);
#else
        secp256k1_pubkey pubkey;
        unsigned char compressed[33];
        size_t compressed_len = 33;

        if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey, parent->privkey.data)) {
            return NOSTR_ERR_INVALID_KEY;
        }

        if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, compressed, &compressed_len, &pubkey, SECP256K1_EC_COMPRESSED)) {
            return NOSTR_ERR_INVALID_KEY;
        }

        memcpy(data, compressed, 33);
#endif
        memcpy(data + 33, &index_be, 4);
    }
    
    if (!HMAC(EVP_sha512(), parent->chain_code, 32, data, 37, hash, &hash_len)) {
        return NOSTR_ERR_MEMORY;
    }
    
    memcpy(child->chain_code, hash + 32, 32);
    
#ifdef HAVE_NOSCRYPT
    NCSecretKey parent_seckey, child_seckey;
    uint8_t tweak[32];
    
    memcpy(parent_seckey.key, parent->privkey.data, 32);
    memcpy(tweak, hash, 32);
    
    memcpy(child_seckey.key, parent_seckey.key, 32);
    
    int carry = 0;
    for (int i = 0; i < 32; i++) {
        int sum = child_seckey.key[31-i] + tweak[31-i] + carry;
        child_seckey.key[31-i] = sum & 0xff;
        carry = sum >> 8;
    }
    
    NCPublicKey nc_pubkey;
    if (NCGetPublicKey(nc_ctx, &child_seckey, &nc_pubkey) != NC_SUCCESS) {
        secure_wipe(hash, 64);
        secure_wipe(&parent_seckey, sizeof(parent_seckey));
        secure_wipe(&child_seckey, sizeof(child_seckey));
        return NOSTR_ERR_INVALID_KEY;
    }
    
    memcpy(child->privkey.data, child_seckey.key, 32);
    memcpy(child->pubkey.data, nc_pubkey.key, 32);
    
    secure_wipe(&parent_seckey, sizeof(parent_seckey));
    secure_wipe(&child_seckey, sizeof(child_seckey));
#else
    secp256k1_keypair child_keypair;
    unsigned char child_privkey[32];
    
    memcpy(child_privkey, parent->privkey.data, 32);
    
    if (!secp256k1_ec_seckey_tweak_add(secp256k1_ctx, child_privkey, hash)) {
        secure_wipe(hash, 64);
        secure_wipe(child_privkey, 32);
        return NOSTR_ERR_INVALID_KEY;
    }
    
    memcpy(child->privkey.data, child_privkey, 32);
    
    if (!secp256k1_keypair_create(secp256k1_ctx, &child_keypair, child_privkey)) {
        secure_wipe(hash, 64);
        secure_wipe(child_privkey, 32);
        return NOSTR_ERR_INVALID_KEY;
    }
    
    secp256k1_xonly_pubkey xonly_pubkey;
    if (!secp256k1_keypair_xonly_pub(secp256k1_ctx, &xonly_pubkey, NULL, &child_keypair)) {
        secure_wipe(hash, 64);
        secure_wipe(child_privkey, 32);
        secure_wipe(&child_keypair, sizeof(child_keypair));
        return NOSTR_ERR_INVALID_KEY;
    }
    
    if (!secp256k1_xonly_pubkey_serialize(secp256k1_ctx, child->pubkey.data, &xonly_pubkey)) {
        secure_wipe(hash, 64);
        secure_wipe(child_privkey, 32);
        secure_wipe(&child_keypair, sizeof(child_keypair));
        return NOSTR_ERR_INVALID_KEY;
    }
    
    secure_wipe(child_privkey, 32);
    secure_wipe(&child_keypair, sizeof(child_keypair));
#endif
    
    secure_wipe(hash, 64);
    return NOSTR_OK;
}

nostr_error_t nostr_hd_key_derive_path(const nostr_hd_key* master, const char* path, nostr_hd_key* derived)
{
    char* path_copy;
    char* token;
    char* saveptr;
    nostr_hd_key current;
    nostr_hd_key next;
    int first = 1;
    
    if (!master || !path || !derived) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (path[0] != 'm' || (path[1] != '\0' && path[1] != '/')) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    memcpy(&current, master, sizeof(nostr_hd_key));
    
    if (path[1] == '\0') {
        memcpy(derived, &current, sizeof(nostr_hd_key));
        return NOSTR_OK;
    }
    
    path_copy = strdup(path + 2);
    if (!path_copy) {
        return NOSTR_ERR_MEMORY;
    }
    
    token = strtok_r(path_copy, "/", &saveptr);
    while (token != NULL) {
        uint32_t index = 0;
        int hardened = 0;
        char* endptr;
        
        if (token[strlen(token) - 1] == '\'' || token[strlen(token) - 1] == 'h') {
            hardened = 1;
            token[strlen(token) - 1] = '\0';
        }
        
        index = strtoul(token, &endptr, 10);
        if (*endptr != '\0' || index >= HD_HARDENED_FLAG) {
            free(path_copy);
            if (!first) {
                secure_wipe(&current, sizeof(current));
            }
            return NOSTR_ERR_INVALID_PARAM;
        }
        
        if (hardened) {
            index |= HD_HARDENED_FLAG;
        }
        
        nostr_error_t err = nostr_hd_key_derive(&current, index, &next);
        if (err != NOSTR_OK) {
            free(path_copy);
            if (!first) {
                secure_wipe(&current, sizeof(current));
            }
            return err;
        }
        
        if (!first) {
            secure_wipe(&current, sizeof(current));
        }
        memcpy(&current, &next, sizeof(nostr_hd_key));
        secure_wipe(&next, sizeof(next));
        
        first = 0;
        token = strtok_r(NULL, "/", &saveptr);
    }
    
    free(path_copy);
    memcpy(derived, &current, sizeof(nostr_hd_key));
    if (!first) {
        secure_wipe(&current, sizeof(current));
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_hd_key_to_keypair(const nostr_hd_key* hd_key, nostr_keypair* keypair)
{
    if (!hd_key || !keypair) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    memset(keypair, 0, sizeof(nostr_keypair));

    memcpy(&keypair->privkey, &hd_key->privkey, sizeof(nostr_privkey));
    memcpy(&keypair->pubkey, &hd_key->pubkey, sizeof(nostr_key));
    keypair->initialized = 1;

    return NOSTR_OK;
}

static int bip39_word_index(const char* word)
{
    for (int i = 0; i < BIP39_WORDLIST_SIZE; i++) {
        if (strcmp(word, bip39_wordlist[i]) == 0) {
            return i;
        }
    }
    return -1;
}

nostr_error_t nostr_mnemonic_generate(int word_count, char* mnemonic, size_t mnemonic_size)
{
    int entropy_bits;
    int entropy_bytes;
    uint8_t entropy[32];
    uint8_t hash[SHA256_DIGEST_LENGTH];
    uint8_t combined[34];

    if (!mnemonic || mnemonic_size == 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (word_count == 12) {
        entropy_bits = 128;
    } else if (word_count == 24) {
        entropy_bits = 256;
    } else {
        return NOSTR_ERR_INVALID_PARAM;
    }

    entropy_bytes = entropy_bits / 8;

    if (nostr_random_bytes(entropy, entropy_bytes) != 1) {
        return NOSTR_ERR_MEMORY;
    }

    SHA256(entropy, entropy_bytes, hash);

    memcpy(combined, entropy, entropy_bytes);
    combined[entropy_bytes] = hash[0];

    size_t pos = 0;

    for (int i = 0; i < word_count; i++) {
        int bit_offset = i * 11;
        int byte_offset = bit_offset / 8;
        int bit_shift = bit_offset % 8;

        uint32_t word_index = 0;
        word_index = ((uint32_t)combined[byte_offset] << 16) |
                     ((uint32_t)combined[byte_offset + 1] << 8) |
                     ((uint32_t)combined[byte_offset + 2]);
        word_index = (word_index >> (24 - 11 - bit_shift)) & 0x7FF;

        const char* word = bip39_wordlist[word_index];
        size_t word_len = strlen(word);

        if (pos + word_len + (i > 0 ? 1 : 0) >= mnemonic_size) {
            secure_wipe(entropy, sizeof(entropy));
            secure_wipe(combined, sizeof(combined));
            return NOSTR_ERR_INVALID_PARAM;
        }

        if (i > 0) {
            mnemonic[pos++] = ' ';
        }
        memcpy(mnemonic + pos, word, word_len);
        pos += word_len;
    }
    mnemonic[pos] = '\0';

    secure_wipe(entropy, sizeof(entropy));
    secure_wipe(combined, sizeof(combined));

    return NOSTR_OK;
}

nostr_error_t nostr_mnemonic_validate(const char* mnemonic)
{
    char* mnemonic_copy;
    char* word;
    char* saveptr;
    int word_count = 0;
    int indices[24];
    int entropy_bits;
    int checksum_bits;
    uint8_t entropy[33];
    uint8_t hash[SHA256_DIGEST_LENGTH];

    if (!mnemonic || strlen(mnemonic) == 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    mnemonic_copy = strdup(mnemonic);
    if (!mnemonic_copy) {
        return NOSTR_ERR_MEMORY;
    }

    word = strtok_r(mnemonic_copy, " ", &saveptr);
    while (word != NULL && word_count < 24) {
        int idx = bip39_word_index(word);
        if (idx < 0) {
            secure_wipe(mnemonic_copy, strlen(mnemonic_copy));
            free(mnemonic_copy);
            return NOSTR_ERR_INVALID_PARAM;
        }
        indices[word_count++] = idx;
        word = strtok_r(NULL, " ", &saveptr);
    }

    secure_wipe(mnemonic_copy, strlen(mnemonic_copy));
    free(mnemonic_copy);

    if (word_count != 12 && word_count != 24) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (word_count == 12) {
        entropy_bits = 128;
        checksum_bits = 4;
    } else {
        entropy_bits = 256;
        checksum_bits = 8;
    }

    memset(entropy, 0, sizeof(entropy));
    for (int i = 0; i < word_count; i++) {
        int bit_offset = i * 11;
        for (int b = 0; b < 11; b++) {
            int bit_pos = bit_offset + b;
            int byte_idx = bit_pos / 8;
            int bit_idx = 7 - (bit_pos % 8);
            if (indices[i] & (1 << (10 - b))) {
                entropy[byte_idx] |= (1 << bit_idx);
            }
        }
    }

    int entropy_bytes = entropy_bits / 8;
    SHA256(entropy, entropy_bytes, hash);

    uint8_t checksum_mask = (1 << checksum_bits) - 1;
    uint8_t expected_checksum = (hash[0] >> (8 - checksum_bits)) & checksum_mask;
    uint8_t actual_checksum = entropy[entropy_bytes] >> (8 - checksum_bits);

    secure_wipe(entropy, sizeof(entropy));

    uint8_t diff = expected_checksum ^ actual_checksum;
    if (diff != 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    return NOSTR_OK;
}

nostr_error_t nostr_mnemonic_to_seed(const char* mnemonic, const char* passphrase, uint8_t seed[64])
{
    const char* salt_prefix = "mnemonic";
    size_t salt_len;
    char* salt;

    if (!mnemonic || !seed) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    salt_len = strlen(salt_prefix) + (passphrase ? strlen(passphrase) : 0) + 1;
    salt = malloc(salt_len);
    if (!salt) {
        return NOSTR_ERR_MEMORY;
    }

    strcpy(salt, salt_prefix);
    if (passphrase) {
        strcat(salt, passphrase);
    }

    if (PKCS5_PBKDF2_HMAC(mnemonic, strlen(mnemonic),
                          (unsigned char*)salt, strlen(salt),
                          2048, EVP_sha512(), 64, seed) != 1) {
        secure_wipe(salt, salt_len);
        free(salt);
        return NOSTR_ERR_MEMORY;
    }

    secure_wipe(salt, salt_len);
    free(salt);

    return NOSTR_OK;
}

nostr_error_t nostr_mnemonic_to_keypair(const char* mnemonic, const char* passphrase,
                                        uint32_t account, nostr_keypair* keypair)
{
    uint8_t seed[64];
    nostr_hd_key master;
    nostr_hd_key derived;
    char path[64];
    nostr_error_t err;

    if (!mnemonic || !keypair) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    err = nostr_mnemonic_validate(mnemonic);
    if (err != NOSTR_OK) {
        return err;
    }

    err = nostr_mnemonic_to_seed(mnemonic, passphrase, seed);
    if (err != NOSTR_OK) {
        return err;
    }

    err = nostr_hd_key_from_seed(seed, 64, &master);
    secure_wipe(seed, sizeof(seed));
    if (err != NOSTR_OK) {
        return err;
    }

    snprintf(path, sizeof(path), "m/44'/1237'/%u'/0/0", account);

    err = nostr_hd_key_derive_path(&master, path, &derived);
    secure_wipe(&master, sizeof(master));
    if (err != NOSTR_OK) {
        return err;
    }

    err = nostr_hd_key_to_keypair(&derived, keypair);
    secure_wipe(&derived, sizeof(derived));

    return err;
}

#else

nostr_error_t nostr_hd_key_from_seed(const uint8_t* seed, size_t seed_len, nostr_hd_key* hd_key) {
    (void)seed; (void)seed_len; (void)hd_key;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_hd_key_derive(const nostr_hd_key* parent, uint32_t index, bool hardened, nostr_hd_key* child) {
    (void)parent; (void)index; (void)hardened; (void)child;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_hd_key_derive_path(const nostr_hd_key* master, const char* path, nostr_hd_key* derived) {
    (void)master; (void)path; (void)derived;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_hd_key_to_keypair(const nostr_hd_key* hd_key, nostr_keypair* keypair) {
    (void)hd_key; (void)keypair;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_mnemonic_generate(int word_count, char* mnemonic, size_t mnemonic_size) {
    (void)word_count; (void)mnemonic; (void)mnemonic_size;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_mnemonic_validate(const char* mnemonic) {
    (void)mnemonic;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_mnemonic_to_seed(const char* mnemonic, const char* passphrase, uint8_t seed[64]) {
    (void)mnemonic; (void)passphrase; (void)seed;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_mnemonic_to_keypair(const char* mnemonic, const char* passphrase,
                                        uint32_t account, nostr_keypair* keypair) {
    (void)mnemonic; (void)passphrase; (void)account; (void)keypair;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif /* NOSTR_FEATURE_HD_KEYS */