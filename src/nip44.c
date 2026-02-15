#include "nostr.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
#include <noscrypt.h>

#ifdef HAVE_MBEDTLS
#include <mbedtls/base64.h>
#include <mbedtls/cipher.h>
#ifdef ESP_PLATFORM
#include <esp_random.h>
#define RAND_bytes(buf, len) (esp_fill_random(buf, len), 1)
#else
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
static int RAND_bytes(uint8_t* buf, size_t len) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret == 0) ret = mbedtls_ctr_drbg_random(&ctr_drbg, buf, len);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret == 0 ? 1 : 0;
}
#endif
#else
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/buffer.h>
#endif

extern NCContext* nc_ctx;
extern nostr_error_t nostr_init(void);

#define NIP44_VERSION 0x02
#define NIP44_NONCE_SIZE 32

static uint32_t calc_padded_len(uint32_t unpadded_len)
{
    uint32_t chunk, next_power;
    
    if (unpadded_len <= 32) {
        return 32;
    }
    
    next_power = 1;
    while (next_power <= unpadded_len) {
        if (next_power > (UINT32_MAX >> 1)) {
            return 0;
        }
        next_power <<= 1;
    }
    next_power >>= 1;
    
    if (next_power <= 256) {
        chunk = 32;
    } else {
        chunk = next_power / 8;
    }
    
    return chunk * (((unpadded_len - 1) / chunk) + 1);
}

static int pad_plaintext(const uint8_t* plaintext, size_t plaintext_len, 
                        uint8_t** padded, size_t* padded_len)
{
    uint32_t pad_len;
    uint8_t* result;
    
    const nostr_config* config = nostr_config_get_current();
    uint32_t min_size = config ? config->nip44_min_plaintext_size : 1;
    uint32_t max_size = config ? config->nip44_max_plaintext_size : 65535;
    
    if (plaintext_len < min_size || plaintext_len > max_size) {
        return -1;
    }
    
    pad_len = 2 + calc_padded_len(plaintext_len);
    result = calloc(1, pad_len);
    if (!result) {
        return -1;
    }

    result[0] = (plaintext_len >> 8) & 0xFF;
    result[1] = plaintext_len & 0xFF;
    memcpy(result + 2, plaintext, plaintext_len);

    *padded = result;
    *padded_len = pad_len;
    
    return 0;
}

static int unpad_plaintext(const uint8_t* padded, size_t padded_len,
                          uint8_t** plaintext, size_t* plaintext_len)
{
    uint16_t unpadded_len;
    uint8_t* result;
    uint32_t expected_pad_len;
    
    if (padded_len < 2) {
        return -1;
    }
    
    unpadded_len = (padded[0] << 8) | padded[1];
    
    const nostr_config* config = nostr_config_get_current();
    uint32_t max_size = config ? config->nip44_max_plaintext_size : 65535;
    
    if (unpadded_len == 0 || unpadded_len > max_size) {
        return -1;
    }

    expected_pad_len = 2 + calc_padded_len(unpadded_len);
    if (padded_len != expected_pad_len) {
        return -1;
    }
    
    result = malloc(unpadded_len);
    if (!result) {
        return -1;
    }
    
    memcpy(result, padded + 2, unpadded_len);
    
    *plaintext = result;
    *plaintext_len = unpadded_len;
    
    return 0;
}

#ifdef HAVE_MBEDTLS
static int base64_encode(const uint8_t* input, size_t input_len, char** output)
{
    size_t olen = 0;
    mbedtls_base64_encode(NULL, 0, &olen, input, input_len);

    *output = malloc(olen + 1);
    if (!*output) {
        return -1;
    }

    if (mbedtls_base64_encode((unsigned char*)*output, olen + 1, &olen, input, input_len) != 0) {
        free(*output);
        return -1;
    }

    (*output)[olen] = '\0';
    return 0;
}

static int base64_decode(const char* input, uint8_t** output, size_t* output_len)
{
    size_t input_len = strlen(input);
    size_t olen = 0;

    mbedtls_base64_decode(NULL, 0, &olen, (const unsigned char*)input, input_len);

    *output = malloc(olen);
    if (!*output) {
        return -1;
    }

    if (mbedtls_base64_decode(*output, olen, output_len, (const unsigned char*)input, input_len) != 0) {
        free(*output);
        return -1;
    }

    return 0;
}
#else
static int base64_encode(const uint8_t* input, size_t input_len, char** output)
{
    BIO* bmem = NULL;
    BIO* b64 = NULL;
    BUF_MEM* bptr = NULL;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(b64, input, input_len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    *output = malloc(bptr->length + 1);
    if (!*output) {
        BIO_free_all(b64);
        return -1;
    }

    memcpy(*output, bptr->data, bptr->length);
    (*output)[bptr->length] = '\0';

    BIO_free_all(b64);
    return 0;
}
#endif

#if !defined(HAVE_MBEDTLS) && defined(ESP_PLATFORM)
static int base64_decode(const char* input, uint8_t** output, size_t* output_len)
{
    size_t input_len = strlen(input);
    size_t olen = 0;

    mbedtls_base64_decode(NULL, 0, &olen, (const unsigned char*)input, input_len);

    *output = malloc(olen);
    if (!*output) {
        return -1;
    }

    if (mbedtls_base64_decode(*output, olen, output_len, (const unsigned char*)input, input_len) != 0) {
        free(*output);
        return -1;
    }

    return 0;
}
#elif !defined(HAVE_MBEDTLS)
static int base64_decode(const char* input, uint8_t** output, size_t* output_len)
{
    BIO* b64 = NULL;
    BIO* bmem = NULL;
    size_t input_len = strlen(input);

    *output = malloc(input_len);
    if (!*output) {
        return -1;
    }

    bmem = BIO_new_mem_buf(input, input_len);
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

    *output_len = BIO_read(bmem, *output, input_len);
    BIO_free_all(bmem);

    if (*output_len <= 0) {
        free(*output);
        return -1;
    }

    return 0;
}
#endif

nostr_error_t nostr_nip44_encrypt(const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey, 
                                  const char* plaintext, size_t plaintext_len, char** ciphertext)
{
    NCEncryptionArgs enc_args = {0};
    uint8_t nonce[NIP44_NONCE_SIZE];
    uint8_t hmac_key[NC_HMAC_KEY_SIZE];
    uint8_t* padded_plaintext = NULL;
    size_t padded_len = 0;
    uint8_t* encrypted = NULL;
    uint8_t* payload = NULL;
    size_t payload_len;
    uint8_t mac[NC_ENCRYPTION_MAC_SIZE];
    NCSecretKey nc_secret;
    NCPublicKey nc_public;
    NCResult result;
    
    if (!sender_privkey || !recipient_pubkey || !plaintext || !ciphertext) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (!nc_ctx) {
        nostr_error_t err = nostr_init();
        if (err != NOSTR_OK) {
            return err;
        }
    }

    uint32_t iv_size = NCEncryptionGetIvSize(NC_ENC_VERSION_NIP44);
    if (iv_size != NIP44_NONCE_SIZE) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    memcpy(nc_secret.key, sender_privkey->data, NC_SEC_KEY_SIZE);
    memcpy(nc_public.key, recipient_pubkey->data, NC_PUBKEY_SIZE);

    nostr_error_t ret = NOSTR_OK;

#ifdef ESP_PLATFORM
    esp_fill_random(nonce, NIP44_NONCE_SIZE);
#else
    if (RAND_bytes(nonce, NIP44_NONCE_SIZE) != 1) {
        ret = NOSTR_ERR_MEMORY;
        goto encrypt_cleanup;
    }
#endif

    if (pad_plaintext((const uint8_t*)plaintext, plaintext_len,
                     &padded_plaintext, &padded_len) != 0) {
        ret = NOSTR_ERR_MEMORY;
        goto encrypt_cleanup;
    }

    encrypted = malloc(padded_len);
    if (!encrypted) {
        ret = NOSTR_ERR_MEMORY;
        goto encrypt_cleanup;
    }

    if (NCEncryptionSetProperty(&enc_args, NC_ENC_SET_VERSION, NC_ENC_VERSION_NIP44) != NC_SUCCESS ||
        NCEncryptionSetPropertyEx(&enc_args, NC_ENC_SET_IV, nonce, NIP44_NONCE_SIZE) != NC_SUCCESS ||
        NCEncryptionSetPropertyEx(&enc_args, NC_ENC_SET_NIP44_MAC_KEY, hmac_key, sizeof(hmac_key)) != NC_SUCCESS ||
        NCEncryptionSetData(&enc_args, padded_plaintext, encrypted, padded_len) != NC_SUCCESS) {
        ret = NOSTR_ERR_INVALID_PARAM;
        goto encrypt_cleanup;
    }

    result = NCEncrypt(nc_ctx, &nc_secret, &nc_public, &enc_args);
    free(padded_plaintext);
    padded_plaintext = NULL;
    if (result != NC_SUCCESS) {
        ret = NOSTR_ERR_INVALID_SIGNATURE;
        goto encrypt_cleanup;
    }

    {
        uint8_t* mac_input = malloc(NIP44_NONCE_SIZE + padded_len);
        if (!mac_input) {
            ret = NOSTR_ERR_MEMORY;
            goto encrypt_cleanup;
        }
        memcpy(mac_input, nonce, NIP44_NONCE_SIZE);
        memcpy(mac_input + NIP44_NONCE_SIZE, encrypted, padded_len);
        result = NCComputeMac(nc_ctx, hmac_key, mac_input, NIP44_NONCE_SIZE + padded_len, mac);
        free(mac_input);
    }

    if (result != NC_SUCCESS) {
        ret = NOSTR_ERR_INVALID_SIGNATURE;
        goto encrypt_cleanup;
    }

    payload_len = 1 + NIP44_NONCE_SIZE + padded_len + NC_ENCRYPTION_MAC_SIZE;
    payload = malloc(payload_len);
    if (!payload) {
        ret = NOSTR_ERR_MEMORY;
        goto encrypt_cleanup;
    }

    payload[0] = NIP44_VERSION;
    memcpy(payload + 1, nonce, NIP44_NONCE_SIZE);
    memcpy(payload + 1 + NIP44_NONCE_SIZE, encrypted, padded_len);
    memcpy(payload + 1 + NIP44_NONCE_SIZE + padded_len, mac, NC_ENCRYPTION_MAC_SIZE);

    free(encrypted);
    encrypted = NULL;

    if (base64_encode(payload, payload_len, ciphertext) != 0) {
        ret = NOSTR_ERR_MEMORY;
    }

encrypt_cleanup:
    free(padded_plaintext);
    free(encrypted);
    free(payload);
    secure_wipe(&nc_secret, sizeof(nc_secret));
    secure_wipe(hmac_key, sizeof(hmac_key));
    return ret;
}

nostr_error_t nostr_nip44_decrypt(const nostr_privkey* recipient_privkey, const nostr_key* sender_pubkey,
                                  const char* ciphertext, char** plaintext, size_t* plaintext_len)
{
    uint8_t* payload = NULL;
    size_t payload_len;
    uint8_t version;
    uint8_t* nonce;
    uint8_t* encrypted_data;
    uint8_t* mac;
    size_t encrypted_len;
    NCEncryptionArgs enc_args = {0};
    NCSecretKey nc_secret;
    NCPublicKey nc_public;
    uint8_t* decrypted = NULL;
    uint8_t* unpadded = NULL;
    size_t unpadded_len;
    NCResult result;
    
    if (!recipient_privkey || !sender_pubkey || !ciphertext || !plaintext || !plaintext_len) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (!nc_ctx) {
        nostr_error_t err = nostr_init();
        if (err != NOSTR_OK) {
            return err;
        }
    }
    
    if (ciphertext[0] == '#') {
        return NOSTR_ERR_NOT_SUPPORTED;
    }
    
    if (base64_decode(ciphertext, &payload, &payload_len) != 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (payload_len < 97 || payload_len > 65600) {
        free(payload);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    version = payload[0];
    if (version != NIP44_VERSION) {
        free(payload);
        return NOSTR_ERR_NOT_SUPPORTED;
    }
    
    nonce = payload + 1;
    encrypted_len = payload_len - 1 - NIP44_NONCE_SIZE - NC_ENCRYPTION_MAC_SIZE;
    encrypted_data = payload + 1 + NIP44_NONCE_SIZE;
    mac = payload + payload_len - NC_ENCRYPTION_MAC_SIZE;
    
    memcpy(nc_secret.key, recipient_privkey->data, NC_SEC_KEY_SIZE);
    memcpy(nc_public.key, sender_pubkey->data, NC_PUBKEY_SIZE);

    nostr_error_t ret = NOSTR_OK;

    uint8_t* mac_payload = malloc(NIP44_NONCE_SIZE + encrypted_len);
    if (!mac_payload) {
        ret = NOSTR_ERR_MEMORY;
        goto decrypt_cleanup;
    }
    memcpy(mac_payload, nonce, NIP44_NONCE_SIZE);
    memcpy(mac_payload + NIP44_NONCE_SIZE, encrypted_data, encrypted_len);

    NCMacVerifyArgs mac_args = {0};
    mac_args.mac32 = mac;
    mac_args.nonce32 = nonce;
    mac_args.payload = mac_payload;
    mac_args.payloadSize = (uint32_t)(NIP44_NONCE_SIZE + encrypted_len);

    result = NCVerifyMac(nc_ctx, &nc_secret, &nc_public, &mac_args);
    secure_wipe(mac_payload, NIP44_NONCE_SIZE + encrypted_len);
    free(mac_payload);
    if (result != NC_SUCCESS) {
        ret = NOSTR_ERR_INVALID_SIGNATURE;
        goto decrypt_cleanup;
    }

    decrypted = calloc(1, encrypted_len);
    if (!decrypted) {
        ret = NOSTR_ERR_MEMORY;
        goto decrypt_cleanup;
    }

    memset(&enc_args, 0, sizeof(enc_args));

    if (NCEncryptionSetProperty(&enc_args, NC_ENC_SET_VERSION, NC_ENC_VERSION_NIP44) != NC_SUCCESS ||
        NCEncryptionSetPropertyEx(&enc_args, NC_ENC_SET_IV, nonce, NIP44_NONCE_SIZE) != NC_SUCCESS ||
        NCEncryptionSetData(&enc_args, encrypted_data, decrypted, encrypted_len) != NC_SUCCESS) {
        ret = NOSTR_ERR_INVALID_PARAM;
        goto decrypt_cleanup;
    }

    result = NCDecrypt(nc_ctx, &nc_secret, &nc_public, &enc_args);
    if (result != NC_SUCCESS) {
        ret = NOSTR_ERR_ENCODING;
        goto decrypt_cleanup;
    }

    if (unpad_plaintext(decrypted, encrypted_len, &unpadded, &unpadded_len) != 0) {
        ret = NOSTR_ERR_INVALID_PARAM;
        goto decrypt_cleanup;
    }

    *plaintext = malloc(unpadded_len + 1);
    if (!*plaintext) {
        ret = NOSTR_ERR_MEMORY;
        goto decrypt_cleanup;
    }

    memcpy(*plaintext, unpadded, unpadded_len);
    (*plaintext)[unpadded_len] = '\0';
    *plaintext_len = unpadded_len;

decrypt_cleanup:
    free(payload);
    free(decrypted);
    free(unpadded);
    secure_wipe(&nc_secret, sizeof(nc_secret));
    return ret;
}

#ifdef HAVE_MBEDTLS
nostr_error_t nostr_nip04_encrypt(const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey,
                                  const char* plaintext, char** ciphertext)
{
    (void)sender_privkey; (void)recipient_pubkey; (void)plaintext; (void)ciphertext;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nip04_decrypt(const nostr_privkey* recipient_privkey, const nostr_key* sender_pubkey,
                                  const char* ciphertext, char** plaintext)
{
    (void)recipient_privkey; (void)sender_pubkey; (void)ciphertext; (void)plaintext;
    return NOSTR_ERR_NOT_SUPPORTED;
}
#else
nostr_error_t nostr_nip04_encrypt(const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey,
                                  const char* plaintext, char** ciphertext)
{
    uint8_t shared_secret[32];
    uint8_t iv[16];
    EVP_CIPHER_CTX* ctx = NULL;
    uint8_t* encrypted = NULL;
    int encrypted_len = 0, final_len = 0;
    char* iv_base64 = NULL;
    char* content_base64 = NULL;
    size_t result_len;
    nostr_error_t result = NOSTR_OK;

    if (!sender_privkey || !recipient_pubkey || !plaintext || !ciphertext) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (nostr_key_ecdh(sender_privkey, recipient_pubkey, shared_secret) != NOSTR_OK) {
        return NOSTR_ERR_INVALID_KEY;
    }

    if (RAND_bytes(iv, 16) != 1) {
        result = NOSTR_ERR_MEMORY;
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        result = NOSTR_ERR_MEMORY;
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, shared_secret, iv) != 1) {
        result = NOSTR_ERR_INVALID_PARAM;
        goto cleanup;
    }

    size_t plaintext_len = strlen(plaintext);
    encrypted = malloc(plaintext_len + AES_BLOCK_SIZE);
    if (!encrypted) {
        result = NOSTR_ERR_MEMORY;
        goto cleanup;
    }

    if (EVP_EncryptUpdate(ctx, encrypted, &encrypted_len, (const uint8_t*)plaintext, plaintext_len) != 1) {
        result = NOSTR_ERR_INVALID_PARAM;
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(ctx, encrypted + encrypted_len, &final_len) != 1) {
        result = NOSTR_ERR_INVALID_PARAM;
        goto cleanup;
    }

    encrypted_len += final_len;

    if (base64_encode(encrypted, encrypted_len, &content_base64) != 0) {
        result = NOSTR_ERR_MEMORY;
        goto cleanup;
    }

    if (base64_encode(iv, 16, &iv_base64) != 0) {
        result = NOSTR_ERR_MEMORY;
        goto cleanup;
    }

    result_len = strlen(content_base64) + strlen(iv_base64) + 5;
    *ciphertext = malloc(result_len);
    if (!*ciphertext) {
        result = NOSTR_ERR_MEMORY;
        goto cleanup;
    }

    snprintf(*ciphertext, result_len, "%s?iv=%s", content_base64, iv_base64);

cleanup:
    secure_wipe(shared_secret, sizeof(shared_secret));
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (encrypted) free(encrypted);
    if (content_base64) free(content_base64);
    if (iv_base64) free(iv_base64);

    return result;
}

nostr_error_t nostr_nip04_decrypt(const nostr_privkey* recipient_privkey, const nostr_key* sender_pubkey,
                                  const char* ciphertext, char** plaintext)
{
    uint8_t shared_secret[32];
    char* content_part = NULL;
    char* iv_part = NULL;
    uint8_t* encrypted_data = NULL;
    size_t encrypted_len;
    uint8_t* iv_data = NULL;
    size_t iv_len;
    EVP_CIPHER_CTX* ctx = NULL;
    uint8_t* decrypted = NULL;
    int decrypted_len = 0, final_len = 0;
    nostr_error_t result = NOSTR_OK;

    if (!recipient_privkey || !sender_pubkey || !ciphertext || !plaintext) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    char* input_copy = strdup(ciphertext);
    if (!input_copy) {
        return NOSTR_ERR_MEMORY;
    }

    char* iv_marker = strstr(input_copy, "?iv=");
    if (!iv_marker) {
        free(input_copy);
        return NOSTR_ERR_INVALID_PARAM;
    }

    *iv_marker = '\0';
    content_part = input_copy;
    iv_part = iv_marker + 4;

    if (base64_decode(content_part, &encrypted_data, &encrypted_len) != 0) {
        result = NOSTR_ERR_INVALID_PARAM;
        goto cleanup;
    }

    if (base64_decode(iv_part, &iv_data, &iv_len) != 0 || iv_len != 16) {
        result = NOSTR_ERR_INVALID_PARAM;
        goto cleanup;
    }

    if (nostr_key_ecdh(recipient_privkey, sender_pubkey, shared_secret) != NOSTR_OK) {
        result = NOSTR_ERR_INVALID_KEY;
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        result = NOSTR_ERR_MEMORY;
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, shared_secret, iv_data) != 1) {
        result = NOSTR_ERR_INVALID_PARAM;
        goto cleanup;
    }

    decrypted = malloc(encrypted_len + AES_BLOCK_SIZE);
    if (!decrypted) {
        result = NOSTR_ERR_MEMORY;
        goto cleanup;
    }

    if (EVP_DecryptUpdate(ctx, decrypted, &decrypted_len, encrypted_data, encrypted_len) != 1) {
        result = NOSTR_ERR_INVALID_PARAM;
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, decrypted + decrypted_len, &final_len) != 1) {
        result = NOSTR_ERR_INVALID_PARAM;
        goto cleanup;
    }

    decrypted_len += final_len;

    *plaintext = malloc(decrypted_len + 1);
    if (!*plaintext) {
        result = NOSTR_ERR_MEMORY;
        goto cleanup;
    }

    memcpy(*plaintext, decrypted, decrypted_len);
    (*plaintext)[decrypted_len] = '\0';

cleanup:
    secure_wipe(shared_secret, sizeof(shared_secret));
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (input_copy) free(input_copy);
    if (encrypted_data) free(encrypted_data);
    if (iv_data) free(iv_data);
    if (decrypted) {
        secure_wipe(decrypted, encrypted_len + AES_BLOCK_SIZE);
        free(decrypted);
    }

    return result;
}
#endif

#else

nostr_error_t nostr_nip44_encrypt(const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey, 
                                  const char* plaintext, size_t plaintext_len, char** ciphertext)
{
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nip44_decrypt(const nostr_privkey* recipient_privkey, const nostr_key* sender_pubkey,
                                  const char* ciphertext, char** plaintext, size_t* plaintext_len)
{
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nip04_encrypt(const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey, 
                                  const char* plaintext, char** ciphertext)
{
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nip04_decrypt(const nostr_privkey* recipient_privkey, const nostr_key* sender_pubkey,
                                  const char* ciphertext, char** plaintext)
{
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif