#include "nostr.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef NOSTR_FEATURE_THREADING
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif
#endif
#ifdef HAVE_NOSCRYPT
#include <noscrypt.h>
#endif
#ifdef HAVE_SECP256K1
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_ecdh.h>
#endif
#ifdef HAVE_MBEDTLS
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#ifdef ESP_PLATFORM
#include <esp_random.h>
#endif
#else
#include <openssl/rand.h>
#include <openssl/sha.h>
#endif

#ifdef HAVE_NOSCRYPT
NCContext* nc_ctx = NULL;
#endif
#ifdef HAVE_SECP256K1
secp256k1_context* secp256k1_ctx = NULL;
#endif
static int ctx_initialized = 0;

#ifdef NOSTR_FEATURE_THREADING
#ifdef _WIN32
static CRITICAL_SECTION ctx_init_lock;
static volatile int ctx_init_lock_initialized = 0;
#else
static pthread_mutex_t ctx_init_lock = PTHREAD_MUTEX_INITIALIZER;
#endif
#endif

static void lock_ctx_init(void) {
#ifdef NOSTR_FEATURE_THREADING
#ifdef _WIN32
    if (!ctx_init_lock_initialized) {
        InitializeCriticalSection(&ctx_init_lock);
        ctx_init_lock_initialized = 1;
    }
    EnterCriticalSection(&ctx_init_lock);
#else
    pthread_mutex_lock(&ctx_init_lock);
#endif
#endif
}

static void unlock_ctx_init(void) {
#ifdef NOSTR_FEATURE_THREADING
#ifdef _WIN32
    LeaveCriticalSection(&ctx_init_lock);
#else
    pthread_mutex_unlock(&ctx_init_lock);
#endif
#endif
}

#ifdef HAVE_MBEDTLS
#ifndef ESP_PLATFORM
static mbedtls_entropy_context rng_entropy;
static mbedtls_ctr_drbg_context rng_ctr_drbg;
static volatile int rng_initialized = 0;
#endif
#endif

int nostr_random_bytes(uint8_t *buf, size_t len) {
#ifdef HAVE_MBEDTLS
#ifdef ESP_PLATFORM
    esp_fill_random(buf, len);
    return 1;
#else
    if (!rng_initialized) {
        lock_ctx_init();
        if (!rng_initialized) {
            mbedtls_entropy_init(&rng_entropy);
            mbedtls_ctr_drbg_init(&rng_ctr_drbg);
            if (mbedtls_ctr_drbg_seed(&rng_ctr_drbg, mbedtls_entropy_func, &rng_entropy, NULL, 0) != 0) {
                unlock_ctx_init();
                return 0;
            }
            rng_initialized = 1;
        }
        unlock_ctx_init();
    }
    return mbedtls_ctr_drbg_random(&rng_ctr_drbg, buf, len) == 0 ? 1 : 0;
#endif
#else
    return RAND_bytes(buf, len);
#endif
}

nostr_error_t nostr_init(void)
{
    lock_ctx_init();
    
    if (ctx_initialized) {
        unlock_ctx_init();
        return NOSTR_OK;
    }

#ifdef HAVE_NOSCRYPT
    // Get shared context
    nc_ctx = NCGetSharedContext();
    if (!nc_ctx) {
        unlock_ctx_init();
        return NOSTR_ERR_MEMORY;
    }
    
    // Generate entropy for initialization
    uint8_t entropy[NC_CONTEXT_ENTROPY_SIZE];
    if (nostr_random_bytes(entropy, NC_CONTEXT_ENTROPY_SIZE) != 1) {
        unlock_ctx_init();
        return NOSTR_ERR_MEMORY;
    }
    
    if (NCInitContext(nc_ctx, entropy) != NC_SUCCESS) {
        unlock_ctx_init();
        return NOSTR_ERR_MEMORY;
    }
#elif defined(HAVE_SECP256K1)
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!secp256k1_ctx) {
        unlock_ctx_init();
        return NOSTR_ERR_MEMORY;
    }
#else
    // No crypto backend available
    unlock_ctx_init();
    return NOSTR_ERR_NOT_SUPPORTED;
#endif

    ctx_initialized = 1;
    unlock_ctx_init();
    return NOSTR_OK;
}

void nostr_cleanup(void)
{
    lock_ctx_init();
    
#ifdef HAVE_NOSCRYPT
    if (nc_ctx) {
        NCDestroyContext(nc_ctx);
        nc_ctx = NULL;
        ctx_initialized = 0;
    }
#elif defined(HAVE_SECP256K1)
    if (secp256k1_ctx) {
        secp256k1_context_destroy(secp256k1_ctx);
        secp256k1_ctx = NULL;
        ctx_initialized = 0;
    }
#endif
    
    unlock_ctx_init();
}


nostr_error_t nostr_key_generate(nostr_privkey* privkey, nostr_key* pubkey)
{
    if (!privkey || !pubkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (!ctx_initialized) {
        nostr_error_t err = nostr_init();
        if (err != NOSTR_OK) {
            return err;
        }
    }

#ifdef HAVE_NOSCRYPT
    // Generate secure random private key
    int attempts = 0;
    NCSecretKey nc_secret;
    NCPublicKey nc_public;
    
    while (attempts < 128) {
        if (nostr_random_bytes(nc_secret.key, NC_SEC_KEY_SIZE) != 1) {
            return NOSTR_ERR_MEMORY;
        }

        // Verify private key is valid using noscrypt
        if (NCValidateSecretKey(nc_ctx, &nc_secret) == NC_SUCCESS) {
            break;
        }
        attempts++;
    }

    if (attempts >= 128) {
        secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
        return NOSTR_ERR_INVALID_KEY;
    }

    // Get public key using noscrypt
    if (NCGetPublicKey(nc_ctx, &nc_secret, &nc_public) != NC_SUCCESS) {
        secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
        return NOSTR_ERR_INVALID_KEY;
    }

    // Copy to our structures
    memcpy(privkey->data, nc_secret.key, NOSTR_PRIVKEY_SIZE);
    memcpy(pubkey->data, nc_public.key, NOSTR_PUBKEY_SIZE);
    
    secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
    
#elif defined(HAVE_SECP256K1)
    // Generate secure random private key
    int attempts = 0;
    while (attempts < 128) {
        if (nostr_random_bytes(privkey->data, NOSTR_PRIVKEY_SIZE) != 1) {
            return NOSTR_ERR_MEMORY;
        }

        // Verify private key is valid for secp256k1
        if (secp256k1_ec_seckey_verify(secp256k1_ctx, privkey->data)) {
            break;
        }
        attempts++;
    }

    if (attempts >= 128) {
        secure_wipe(privkey->data, NOSTR_PRIVKEY_SIZE);
        return NOSTR_ERR_INVALID_KEY;
    }

    // Derive public key
    secp256k1_pubkey pubkey_internal;
    if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey_internal, privkey->data)) {
        secure_wipe(privkey->data, NOSTR_PRIVKEY_SIZE);
        return NOSTR_ERR_INVALID_KEY;
    }

    // Convert to x-only pubkey for Nostr
    secp256k1_xonly_pubkey xonly_pubkey;
    int parity;
    if (!secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &xonly_pubkey, &parity, &pubkey_internal)) {
        secure_wipe(privkey->data, NOSTR_PRIVKEY_SIZE);
        return NOSTR_ERR_INVALID_KEY;
    }

    // Serialize x-only pubkey (32 bytes)
    if (!secp256k1_xonly_pubkey_serialize(secp256k1_ctx, pubkey->data, &xonly_pubkey)) {
        secure_wipe(privkey->data, NOSTR_PRIVKEY_SIZE);
        return NOSTR_ERR_INVALID_KEY;
    }
#else
    // No crypto backend available
    return NOSTR_ERR_NOT_SUPPORTED;
#endif

    return NOSTR_OK;
}

nostr_error_t nostr_key_from_hex(const char* hex, nostr_key* key) {
    if (!hex || !key) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (strlen(hex) != 64) {
        return NOSTR_ERR_INVALID_KEY;
    }
    
    for (int i = 0; i < NOSTR_PUBKEY_SIZE; i++) {
        if (sscanf(hex + i * 2, "%2hhx", &key->data[i]) != 1) {
            return NOSTR_ERR_INVALID_KEY;
        }
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_key_to_hex(const nostr_key* key, char* hex, size_t hex_size) {
    if (!key || !hex || hex_size < 65) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    for (int i = 0; i < NOSTR_PUBKEY_SIZE; i++) {
        sprintf(hex + i * 2, "%02x", key->data[i]);
    }
    hex[64] = '\0';
    
    return NOSTR_OK;
}

nostr_error_t nostr_privkey_from_hex(const char* hex, nostr_privkey* privkey) {
    if (!hex || !privkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (strlen(hex) != 64) {
        return NOSTR_ERR_INVALID_KEY;
    }
    
    for (int i = 0; i < NOSTR_PRIVKEY_SIZE; i++) {
        if (sscanf(hex + i * 2, "%2hhx", &privkey->data[i]) != 1) {
            return NOSTR_ERR_INVALID_KEY;
        }
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_privkey_to_hex(const nostr_privkey* privkey, char* hex, size_t hex_size) {
    if (!privkey || !hex || hex_size < 65) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    for (int i = 0; i < NOSTR_PRIVKEY_SIZE; i++) {
        sprintf(hex + i * 2, "%02x", privkey->data[i]);
    }
    hex[64] = '\0';
    
    return NOSTR_OK;
}

nostr_error_t nostr_key_ecdh(const nostr_privkey* privkey, const nostr_key* pubkey, uint8_t shared_secret[32])
{
    if (!privkey || !pubkey || !shared_secret) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (!ctx_initialized) {
        nostr_error_t err = nostr_init();
        if (err != NOSTR_OK) {
            return err;
        }
    }

#ifdef HAVE_NOSCRYPT
    NCSecretKey nc_secret;
    NCPublicKey nc_public;
    uint8_t shared_point[NC_SHARED_SEC_SIZE];
    
    memcpy(nc_secret.key, privkey->data, NC_SEC_KEY_SIZE);
    memcpy(nc_public.key, pubkey->data, NC_PUBKEY_SIZE);
    
    if (NCGetSharedSecret(nc_ctx, &nc_secret, &nc_public, shared_point) != NC_SUCCESS) {
        secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
        return NOSTR_ERR_INVALID_KEY;
    }
    
    memcpy(shared_secret, shared_point, 32);
    
    secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
    secure_wipe(shared_point, NC_SHARED_SEC_SIZE);
#elif defined(HAVE_SECP256K1)
    secp256k1_pubkey secp_pubkey;
    uint8_t pubkey_serialized[33];
    
    pubkey_serialized[0] = 0x02;
    memcpy(pubkey_serialized + 1, pubkey->data, 32);
    
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &secp_pubkey, pubkey_serialized, 33)) {
        return NOSTR_ERR_INVALID_KEY;
    }
    
    if (!secp256k1_ecdh(secp256k1_ctx, shared_secret, &secp_pubkey, privkey->data, NULL, NULL)) {
        return NOSTR_ERR_INVALID_KEY;
    }
#else
    // No crypto backend available
    return NOSTR_ERR_NOT_SUPPORTED;
#endif

    return NOSTR_OK;
}

nostr_error_t nostr_keypair_init(nostr_keypair* keypair)
{
    if (!keypair) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    memset(keypair, 0, sizeof(nostr_keypair));
    keypair->initialized = 0;
    
    return NOSTR_OK;
}

nostr_error_t nostr_keypair_generate(nostr_keypair* keypair)
{
    if (!keypair) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    nostr_error_t err = nostr_key_generate(&keypair->privkey, &keypair->pubkey);
    if (err != NOSTR_OK) {
        return err;
    }
    
    keypair->initialized = 1;
    return NOSTR_OK;
}

nostr_error_t nostr_keypair_from_private_hex(nostr_keypair* keypair, const char* privkey_hex)
{
    if (!keypair || !privkey_hex) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    nostr_error_t err = nostr_privkey_from_hex(privkey_hex, &keypair->privkey);
    if (err != NOSTR_OK) {
        return err;
    }
    
    return nostr_keypair_from_private_key(keypair, &keypair->privkey);
}

nostr_error_t nostr_keypair_from_private_key(nostr_keypair* keypair, const nostr_privkey* privkey)
{
    if (!keypair || !privkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (!ctx_initialized) {
        nostr_error_t err = nostr_init();
        if (err != NOSTR_OK) {
            return err;
        }
    }
    
    memcpy(&keypair->privkey, privkey, sizeof(nostr_privkey));
    
#ifdef HAVE_NOSCRYPT
    NCSecretKey nc_secret;
    NCPublicKey nc_public;
    
    memcpy(nc_secret.key, privkey->data, NC_SEC_KEY_SIZE);
    
    if (NCValidateSecretKey(nc_ctx, &nc_secret) != NC_SUCCESS) {
        secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
        secure_wipe(&keypair->privkey, sizeof(nostr_privkey));
        return NOSTR_ERR_INVALID_KEY;
    }
    
    if (NCGetPublicKey(nc_ctx, &nc_secret, &nc_public) != NC_SUCCESS) {
        secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
        secure_wipe(&keypair->privkey, sizeof(nostr_privkey));
        return NOSTR_ERR_INVALID_KEY;
    }
    
    memcpy(keypair->pubkey.data, nc_public.key, NOSTR_PUBKEY_SIZE);
    secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
    
#elif defined(HAVE_SECP256K1)
    if (!secp256k1_ec_seckey_verify(secp256k1_ctx, privkey->data)) {
        secure_wipe(&keypair->privkey, sizeof(nostr_privkey));
        return NOSTR_ERR_INVALID_KEY;
    }
    
    secp256k1_pubkey pubkey_internal;
    if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey_internal, privkey->data)) {
        secure_wipe(&keypair->privkey, sizeof(nostr_privkey));
        return NOSTR_ERR_INVALID_KEY;
    }
    
    secp256k1_xonly_pubkey xonly_pubkey;
    int parity;
    if (!secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &xonly_pubkey, &parity, &pubkey_internal)) {
        secure_wipe(&keypair->privkey, sizeof(nostr_privkey));
        return NOSTR_ERR_INVALID_KEY;
    }
    
    if (!secp256k1_xonly_pubkey_serialize(secp256k1_ctx, keypair->pubkey.data, &xonly_pubkey)) {
        secure_wipe(&keypair->privkey, sizeof(nostr_privkey));
        return NOSTR_ERR_INVALID_KEY;
    }
#else
    // No crypto backend available
    secure_wipe(&keypair->privkey, sizeof(nostr_privkey));
    return NOSTR_ERR_NOT_SUPPORTED;
#endif
    
    keypair->initialized = 1;
    return NOSTR_OK;
}

nostr_error_t nostr_keypair_export_private_hex(const nostr_keypair* keypair, char* hex, size_t hex_size)
{
    if (!keypair || !keypair->initialized || !hex) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    return nostr_privkey_to_hex(&keypair->privkey, hex, hex_size);
}

nostr_error_t nostr_keypair_export_public_hex(const nostr_keypair* keypair, char* hex, size_t hex_size)
{
    if (!keypair || !keypair->initialized || !hex) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    return nostr_key_to_hex(&keypair->pubkey, hex, hex_size);
}

nostr_error_t nostr_keypair_validate(const nostr_keypair* keypair)
{
    if (!keypair || !keypair->initialized) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (!ctx_initialized) {
        nostr_error_t err = nostr_init();
        if (err != NOSTR_OK) {
            return err;
        }
    }
    
#ifdef HAVE_NOSCRYPT
    NCSecretKey nc_secret;
    NCPublicKey nc_public;
    NCPublicKey derived_public;
    
    memcpy(nc_secret.key, keypair->privkey.data, NC_SEC_KEY_SIZE);
    memcpy(nc_public.key, keypair->pubkey.data, NC_PUBKEY_SIZE);
    
    if (NCValidateSecretKey(nc_ctx, &nc_secret) != NC_SUCCESS) {
        secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
        return NOSTR_ERR_INVALID_KEY;
    }
    
    if (NCGetPublicKey(nc_ctx, &nc_secret, &derived_public) != NC_SUCCESS) {
        secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
        return NOSTR_ERR_INVALID_KEY;
    }
    
    int keys_match = (nostr_constant_time_memcmp(nc_public.key, derived_public.key, NC_PUBKEY_SIZE) == 0);
    secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
    
    return keys_match ? NOSTR_OK : NOSTR_ERR_INVALID_KEY;
    
#elif defined(HAVE_SECP256K1)
    if (!secp256k1_ec_seckey_verify(secp256k1_ctx, keypair->privkey.data)) {
        return NOSTR_ERR_INVALID_KEY;
    }
    
    secp256k1_pubkey pubkey_internal;
    if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey_internal, keypair->privkey.data)) {
        return NOSTR_ERR_INVALID_KEY;
    }
    
    secp256k1_xonly_pubkey xonly_pubkey;
    int parity;
    if (!secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &xonly_pubkey, &parity, &pubkey_internal)) {
        return NOSTR_ERR_INVALID_KEY;
    }
    
    uint8_t derived_pubkey[NOSTR_PUBKEY_SIZE];
    if (!secp256k1_xonly_pubkey_serialize(secp256k1_ctx, derived_pubkey, &xonly_pubkey)) {
        return NOSTR_ERR_INVALID_KEY;
    }
    
    return (nostr_constant_time_memcmp(keypair->pubkey.data, derived_pubkey, NOSTR_PUBKEY_SIZE) == 0) 
           ? NOSTR_OK : NOSTR_ERR_INVALID_KEY;
#else
    // No crypto backend available
    return NOSTR_ERR_NOT_SUPPORTED;
#endif
}

const nostr_key* nostr_keypair_public_key(const nostr_keypair* keypair)
{
    if (!keypair || !keypair->initialized) {
        return NULL;
    }
    
    return &keypair->pubkey;
}

const nostr_privkey* nostr_keypair_private_key(const nostr_keypair* keypair)
{
    if (!keypair || !keypair->initialized) {
        return NULL;
    }
    
    return &keypair->privkey;
}

void nostr_keypair_destroy(nostr_keypair* keypair)
{
    if (!keypair) {
        return;
    }
    
    secure_wipe(&keypair->privkey, sizeof(nostr_privkey));
    secure_wipe(&keypair->pubkey, sizeof(nostr_key));
    keypair->initialized = 0;
}

const char* nostr_error_string(nostr_error_t error)
{
    switch (error) {
        case NOSTR_OK: return "Success";
        case NOSTR_ERR_INVALID_KEY: return "Invalid key";
        case NOSTR_ERR_INVALID_EVENT: return "Invalid event";
        case NOSTR_ERR_INVALID_SIGNATURE: return "Invalid signature";
        case NOSTR_ERR_MEMORY: return "Memory allocation failed";
        case NOSTR_ERR_JSON_PARSE: return "JSON parsing error";
        case NOSTR_ERR_ENCODING: return "Encoding error";
        case NOSTR_ERR_CONNECTION: return "Connection error";
        case NOSTR_ERR_PROTOCOL: return "Protocol error";
        case NOSTR_ERR_NOT_FOUND: return "Not found";
        case NOSTR_ERR_TIMEOUT: return "Timeout";
        case NOSTR_ERR_INVALID_PARAM: return "Invalid parameter";
        default: return "Unknown error";
    }
}