#include "nostr.h"

#ifdef NOSTR_FEATURE_HD_KEYS

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <arpa/inet.h>

extern void secure_wipe(void* data, size_t len);

#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
#include <noscrypt/noscrypt.h>
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
    
#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
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
#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
        NCPublicKey nc_pubkey;
        memcpy(nc_pubkey.key, parent->pubkey.data, 32);
        
        data[0] = 0x02;
        memcpy(data + 1, parent->pubkey.data, 32);
#else
        secp256k1_pubkey pubkey;
        unsigned char compressed[33];
        size_t compressed_len = 33;
        
        if (!secp256k1_xonly_pubkey_parse(secp256k1_ctx, (secp256k1_xonly_pubkey*)&pubkey, parent->pubkey.data)) {
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
    
#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
    NCSecretKey parent_seckey, child_seckey;
    uint8_t tweak[32];
    
    memcpy(parent_seckey.key, parent->privkey.data, 32);
    memcpy(tweak, hash, 32);
    
    memcpy(child_seckey.key, parent_seckey.key, 32);
    
    for (int i = 0; i < 32; i++) {
        int carry = 0;
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

#else

/* HD key functionality not available */
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

#endif /* NOSTR_FEATURE_HD_KEYS */