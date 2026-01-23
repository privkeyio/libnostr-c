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

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
extern secp256k1_context* secp256k1_ctx;

#ifdef HAVE_NOSCRYPT
#include <noscrypt.h>
extern NCContext* nc_ctx;
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
    if (!parent || !child) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    memset(child, 0, sizeof(nostr_hd_key));

    unsigned char data[37];
    uint32_t index_be = htonl(index);

    if (index & HD_HARDENED_FLAG) {
        data[0] = 0x00;
        memcpy(data + 1, parent->privkey.data, 32);
        memcpy(data + 33, &index_be, 4);
    } else {
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey, parent->privkey.data)) {
            return NOSTR_ERR_INVALID_KEY;
        }

        unsigned char compressed[33];
        size_t compressed_len = 33;
        if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, compressed, &compressed_len, &pubkey, SECP256K1_EC_COMPRESSED)) {
            return NOSTR_ERR_INVALID_KEY;
        }

        memcpy(data, compressed, 33);
        memcpy(data + 33, &index_be, 4);
    }

    unsigned char hash[64];
    unsigned int hash_len = 64;
    
    if (!HMAC(EVP_sha512(), parent->chain_code, 32, data, 37, hash, &hash_len)) {
        return NOSTR_ERR_MEMORY;
    }
    
    memcpy(child->chain_code, hash + 32, 32);
    
    unsigned char child_privkey[32];
    memcpy(child_privkey, parent->privkey.data, 32);

    if (!secp256k1_ec_seckey_tweak_add(secp256k1_ctx, child_privkey, hash)) {
        secure_wipe(hash, 64);
        secure_wipe(data, sizeof(data));
        secure_wipe(child_privkey, 32);
        return NOSTR_ERR_INVALID_KEY;
    }

    memcpy(child->privkey.data, child_privkey, 32);

#ifdef HAVE_NOSCRYPT
    NCSecretKey child_seckey;
    NCPublicKey nc_pubkey;

    memcpy(child_seckey.key, child_privkey, 32);

    if (NCGetPublicKey(nc_ctx, &child_seckey, &nc_pubkey) != NC_SUCCESS) {
        secure_wipe(hash, 64);
        secure_wipe(data, sizeof(data));
        secure_wipe(child_privkey, 32);
        secure_wipe(&child_seckey, sizeof(child_seckey));
        return NOSTR_ERR_INVALID_KEY;
    }

    memcpy(child->pubkey.data, nc_pubkey.key, 32);

    secure_wipe(&child_seckey, sizeof(child_seckey));
#else
    secp256k1_keypair child_keypair;

    if (!secp256k1_keypair_create(secp256k1_ctx, &child_keypair, child_privkey)) {
        secure_wipe(hash, 64);
        secure_wipe(data, sizeof(data));
        secure_wipe(child_privkey, 32);
        return NOSTR_ERR_INVALID_KEY;
    }

    secp256k1_xonly_pubkey xonly_pubkey;
    if (!secp256k1_keypair_xonly_pub(secp256k1_ctx, &xonly_pubkey, NULL, &child_keypair)) {
        secure_wipe(hash, 64);
        secure_wipe(data, sizeof(data));
        secure_wipe(child_privkey, 32);
        secure_wipe(&child_keypair, sizeof(child_keypair));
        return NOSTR_ERR_INVALID_KEY;
    }

    if (!secp256k1_xonly_pubkey_serialize(secp256k1_ctx, child->pubkey.data, &xonly_pubkey)) {
        secure_wipe(hash, 64);
        secure_wipe(data, sizeof(data));
        secure_wipe(child_privkey, 32);
        secure_wipe(&child_keypair, sizeof(child_keypair));
        return NOSTR_ERR_INVALID_KEY;
    }

    secure_wipe(&child_keypair, sizeof(child_keypair));
#endif

    secure_wipe(data, sizeof(data));
    secure_wipe(child_privkey, 32);

    secure_wipe(hash, 64);
    return NOSTR_OK;
}

nostr_error_t nostr_hd_key_derive_path(const nostr_hd_key* master, const char* path, nostr_hd_key* derived)
{
    if (!master || !path || !derived) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (path[0] != 'm' || (path[1] != '\0' && path[1] != '/')) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (path[1] == '\0') {
        memcpy(derived, master, sizeof(nostr_hd_key));
        return NOSTR_OK;
    }

    size_t path_len = strlen(path + 2);
    char* path_copy = strdup(path + 2);
    if (!path_copy) {
        return NOSTR_ERR_MEMORY;
    }

    nostr_hd_key current;
    memcpy(&current, master, sizeof(nostr_hd_key));

    char* saveptr;
    char* token = strtok_r(path_copy, "/", &saveptr);

    while (token != NULL) {
        size_t token_len = strlen(token);
        int hardened = 0;

        if (token_len > 0 && (token[token_len - 1] == '\'' || token[token_len - 1] == 'h')) {
            hardened = 1;
            token[token_len - 1] = '\0';
        }

        char* endptr;
        uint32_t index = strtoul(token, &endptr, 10);
        if (*endptr != '\0' || index >= HD_HARDENED_FLAG) {
            secure_wipe(path_copy, path_len);
            free(path_copy);
            secure_wipe(&current, sizeof(current));
            return NOSTR_ERR_INVALID_PARAM;
        }

        if (hardened) {
            index |= HD_HARDENED_FLAG;
        }

        nostr_hd_key next;
        nostr_error_t err = nostr_hd_key_derive(&current, index, &next);
        if (err != NOSTR_OK) {
            secure_wipe(path_copy, path_len);
            free(path_copy);
            secure_wipe(&current, sizeof(current));
            return err;
        }

        secure_wipe(&current, sizeof(current));
        memcpy(&current, &next, sizeof(nostr_hd_key));
        secure_wipe(&next, sizeof(next));

        token = strtok_r(NULL, "/", &saveptr);
    }

    secure_wipe(path_copy, path_len);
    free(path_copy);
    memcpy(derived, &current, sizeof(nostr_hd_key));
    secure_wipe(&current, sizeof(current));

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
    int left = 0;
    int right = BIP39_WORDLIST_SIZE - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;
        int cmp = strcmp(word, bip39_wordlist[mid]);
        if (cmp == 0) {
            return mid;
        } else if (cmp < 0) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    return -1;
}

nostr_error_t nostr_mnemonic_generate(int word_count, char* mnemonic, size_t mnemonic_size)
{
    if (!mnemonic || mnemonic_size == 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    int entropy_bytes;
    if (word_count == 12) {
        entropy_bytes = 16;
    } else if (word_count == 24) {
        entropy_bytes = 32;
    } else {
        return NOSTR_ERR_INVALID_PARAM;
    }

    uint8_t entropy[32];
    uint8_t hash[SHA256_DIGEST_LENGTH];
    uint8_t combined[34];

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
    if (!mnemonic || strlen(mnemonic) == 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    size_t mnemonic_len = strlen(mnemonic);
    char* mnemonic_copy = strdup(mnemonic);
    if (!mnemonic_copy) {
        return NOSTR_ERR_MEMORY;
    }

    int indices[24] = {0};
    int word_count = 0;
    char* saveptr;
    char* word = strtok_r(mnemonic_copy, " ", &saveptr);

    while (word != NULL && word_count < 24) {
        int idx = bip39_word_index(word);
        if (idx < 0) {
            secure_wipe(mnemonic_copy, mnemonic_len);
            free(mnemonic_copy);
            return NOSTR_ERR_INVALID_PARAM;
        }
        indices[word_count++] = idx;
        word = strtok_r(NULL, " ", &saveptr);
    }

    secure_wipe(mnemonic_copy, mnemonic_len);
    free(mnemonic_copy);

    int entropy_bytes;
    int checksum_bits;
    if (word_count == 12) {
        entropy_bytes = 16;
        checksum_bits = 4;
    } else if (word_count == 24) {
        entropy_bytes = 32;
        checksum_bits = 8;
    } else {
        return NOSTR_ERR_INVALID_PARAM;
    }

    uint8_t entropy[33];
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

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(entropy, entropy_bytes, hash);

    uint8_t checksum_mask = (1 << checksum_bits) - 1;
    uint8_t expected_checksum = (hash[0] >> (8 - checksum_bits)) & checksum_mask;
    uint8_t actual_checksum = entropy[entropy_bytes] >> (8 - checksum_bits);

    secure_wipe(entropy, sizeof(entropy));
    secure_wipe(hash, sizeof(hash));

    if (expected_checksum != actual_checksum) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    return NOSTR_OK;
}

nostr_error_t nostr_mnemonic_to_seed(const char* mnemonic, const char* passphrase, uint8_t seed[64])
{
    if (!mnemonic || !seed) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    nostr_error_t validate_err = nostr_mnemonic_validate(mnemonic);
    if (validate_err != NOSTR_OK) {
        return validate_err;
    }

    const char* salt_prefix = "mnemonic";
    size_t prefix_len = strlen(salt_prefix);
    size_t passphrase_len = passphrase ? strlen(passphrase) : 0;

    if (passphrase_len > SIZE_MAX - prefix_len - 1) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    size_t salt_len = prefix_len + passphrase_len + 1;

    char* salt = malloc(salt_len);
    if (!salt) {
        return NOSTR_ERR_MEMORY;
    }

    strcpy(salt, salt_prefix);
    if (passphrase) {
        strcat(salt, passphrase);
    }

    int result = PKCS5_PBKDF2_HMAC(mnemonic, strlen(mnemonic),
                                   (unsigned char*)salt, strlen(salt),
                                   2048, EVP_sha512(), 64, seed);

    secure_wipe(salt, salt_len);
    free(salt);

    return (result == 1) ? NOSTR_OK : NOSTR_ERR_MEMORY;
}

nostr_error_t nostr_mnemonic_to_keypair(const char* mnemonic, const char* passphrase,
                                        uint32_t account, nostr_keypair* keypair)
{
    if (!mnemonic || !keypair) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    nostr_error_t err = nostr_mnemonic_validate(mnemonic);
    if (err != NOSTR_OK) {
        return err;
    }

    uint8_t seed[64];
    err = nostr_mnemonic_to_seed(mnemonic, passphrase, seed);
    if (err != NOSTR_OK) {
        return err;
    }

    nostr_hd_key master;
    err = nostr_hd_key_from_seed(seed, 64, &master);
    secure_wipe(seed, sizeof(seed));
    if (err != NOSTR_OK) {
        return err;
    }

    char path[64];
    snprintf(path, sizeof(path), "m/44'/1237'/%u'/0/0", account);

    nostr_hd_key derived;
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