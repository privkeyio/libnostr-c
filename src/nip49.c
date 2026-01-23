#include "nostr.h"
#include "bech32_internal.h"
#include <stdlib.h>
#include <string.h>

#ifdef NOSTR_FEATURE_NIP49

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#define NIP49_VERSION           0x02
#define NIP49_SALT_SIZE         16
#define NIP49_NONCE_SIZE        24
#define NIP49_PRIVKEY_SIZE      32
#define NIP49_MAC_SIZE          16
#define NIP49_PAYLOAD_SIZE      91

#define NIP49_KEY_SECURITY_UNKNOWN  0x02

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

static void hchacha20(const uint8_t key[32], const uint8_t nonce[16], uint8_t subkey[32])
{
    static const uint32_t sigma[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    uint32_t state[16];

    state[0] = sigma[0];
    state[1] = sigma[1];
    state[2] = sigma[2];
    state[3] = sigma[3];

    for (int i = 0; i < 8; i++) {
        state[4 + i] = load32_le(key + i * 4);
    }

    for (int i = 0; i < 4; i++) {
        state[12 + i] = load32_le(nonce + i * 4);
    }

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define QR(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);

    for (int i = 0; i < 10; i++) {
        QR(state[0], state[4], state[8],  state[12]);
        QR(state[1], state[5], state[9],  state[13]);
        QR(state[2], state[6], state[10], state[14]);
        QR(state[3], state[7], state[11], state[15]);
        QR(state[0], state[5], state[10], state[15]);
        QR(state[1], state[6], state[11], state[12]);
        QR(state[2], state[7], state[8],  state[13]);
        QR(state[3], state[4], state[9],  state[14]);
    }

#undef QR
#undef ROTL32

    for (int i = 0; i < 4; i++) {
        store32_le(subkey + i * 4, state[i]);
    }
    for (int i = 0; i < 4; i++) {
        store32_le(subkey + 16 + i * 4, state[12 + i]);
    }

    secure_wipe(state, sizeof(state));
}

static int xchacha20_poly1305_encrypt(
    const uint8_t *key,
    const uint8_t *nonce24,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, uint8_t *tag)
{
    uint8_t subkey[32];
    uint8_t nonce12[12];
    EVP_CIPHER_CTX *ctx = NULL;
    int len, ret = 0;

    hchacha20(key, nonce24, subkey);

    memset(nonce12, 0, 4);
    memcpy(nonce12 + 4, nonce24 + 16, 8);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, subkey, nonce12) != 1)
        goto cleanup;

    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1)
            goto cleanup;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        goto cleanup;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, NIP49_MAC_SIZE, tag) != 1)
        goto cleanup;

    ret = 1;

cleanup:
    secure_wipe(subkey, sizeof(subkey));
    secure_wipe(nonce12, sizeof(nonce12));
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int xchacha20_poly1305_decrypt(
    const uint8_t *key,
    const uint8_t *nonce24,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *tag,
    uint8_t *plaintext)
{
    uint8_t subkey[32];
    uint8_t nonce12[12];
    EVP_CIPHER_CTX *ctx = NULL;
    int len, ret = 0;

    hchacha20(key, nonce24, subkey);

    memset(nonce12, 0, 4);
    memcpy(nonce12 + 4, nonce24 + 16, 8);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto cleanup;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1)
        goto cleanup;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, subkey, nonce12) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, NIP49_MAC_SIZE, (void*)tag) != 1)
        goto cleanup;

    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1)
            goto cleanup;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        goto cleanup;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        goto cleanup;

    ret = 1;

cleanup:
    secure_wipe(subkey, sizeof(subkey));
    secure_wipe(nonce12, sizeof(nonce12));
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int derive_key_scrypt(
    const char *password,
    const uint8_t *salt,
    uint8_t log_n,
    uint8_t *key_out)
{
    uint64_t N = (uint64_t)1 << log_n;
    size_t maxmem = (size_t)256 * N * 8;

    return EVP_PBE_scrypt(password, strlen(password),
                          salt, NIP49_SALT_SIZE,
                          N, 8, 1, maxmem,
                          key_out, 32) == 1;
}

static nostr_error_t decode_ncryptsec(const char *ncryptsec, uint8_t *payload)
{
    uint8_t data5bit[160];
    size_t len;

    if (strncmp(ncryptsec, "ncryptsec1", 10) != 0) {
        return NOSTR_ERR_ENCODING;
    }

    len = strlen(ncryptsec);
    if (len < 20 || len > 200) {
        return NOSTR_ERR_ENCODING;
    }

    size_t data_len = len - 10;
    if (data_len > sizeof(data5bit)) {
        return NOSTR_ERR_ENCODING;
    }

    for (size_t i = 0; i < data_len; i++) {
        int val = bech32_charset_decode(ncryptsec[10 + i]);
        if (val == -1) {
            return NOSTR_ERR_ENCODING;
        }
        data5bit[i] = val;
    }

    if (!bech32_verify_checksum("ncryptsec", data5bit, data_len)) {
        return NOSTR_ERR_ENCODING;
    }

    int payload_len = bech32_convert_bits(data5bit, data_len - 6,
                                          payload, NIP49_PAYLOAD_SIZE, 5, 8, 0);
    if (payload_len != NIP49_PAYLOAD_SIZE) {
        return NOSTR_ERR_ENCODING;
    }

    return NOSTR_OK;
}

nostr_error_t nostr_ncryptsec_encrypt(const nostr_privkey *privkey,
                                       const char *password,
                                       uint8_t log_n,
                                       char *ncryptsec,
                                       size_t ncryptsec_size)
{
    uint8_t salt[NIP49_SALT_SIZE];
    uint8_t nonce[NIP49_NONCE_SIZE];
    uint8_t symmetric_key[32];
    uint8_t ciphertext[NIP49_PRIVKEY_SIZE];
    uint8_t mac[NIP49_MAC_SIZE];
    uint8_t payload[NIP49_PAYLOAD_SIZE];

    if (!privkey || !password || !ncryptsec) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (strlen(password) == 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (log_n < 16 || log_n > 22) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (ncryptsec_size < 160) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (RAND_bytes(salt, NIP49_SALT_SIZE) != 1) {
        return NOSTR_ERR_MEMORY;
    }

    if (RAND_bytes(nonce, NIP49_NONCE_SIZE) != 1) {
        return NOSTR_ERR_MEMORY;
    }

    if (!derive_key_scrypt(password, salt, log_n, symmetric_key)) {
        return NOSTR_ERR_ENCODING;
    }

    uint8_t key_security = NIP49_KEY_SECURITY_UNKNOWN;
    if (!xchacha20_poly1305_encrypt(symmetric_key, nonce,
                                    &key_security, 1,
                                    privkey->data, NIP49_PRIVKEY_SIZE,
                                    ciphertext, mac)) {
        secure_wipe(symmetric_key, sizeof(symmetric_key));
        return NOSTR_ERR_ENCODING;
    }

    secure_wipe(symmetric_key, sizeof(symmetric_key));

    uint8_t *p = payload;
    *p++ = NIP49_VERSION;
    *p++ = log_n;
    memcpy(p, salt, NIP49_SALT_SIZE); p += NIP49_SALT_SIZE;
    memcpy(p, nonce, NIP49_NONCE_SIZE); p += NIP49_NONCE_SIZE;
    *p++ = key_security;
    memcpy(p, ciphertext, NIP49_PRIVKEY_SIZE); p += NIP49_PRIVKEY_SIZE;
    memcpy(p, mac, NIP49_MAC_SIZE);

    uint8_t data5bit[146];
    int data5bit_len = bech32_convert_bits(payload, NIP49_PAYLOAD_SIZE,
                                           data5bit, sizeof(data5bit), 8, 5, 1);
    if (data5bit_len <= 0) {
        return NOSTR_ERR_ENCODING;
    }

    uint8_t checksum[6];
    if (!bech32_create_checksum("ncryptsec", data5bit, data5bit_len, checksum)) {
        return NOSTR_ERR_ENCODING;
    }

    memcpy(ncryptsec, "ncryptsec1", 10);
    char *pos = ncryptsec + 10;

    for (int i = 0; i < data5bit_len; i++) {
        *pos++ = BECH32_CHARSET[data5bit[i]];
    }
    for (int i = 0; i < 6; i++) {
        *pos++ = BECH32_CHARSET[checksum[i]];
    }
    *pos = '\0';

    secure_wipe(payload, sizeof(payload));
    secure_wipe(nonce, sizeof(nonce));

    return NOSTR_OK;
}

nostr_error_t nostr_ncryptsec_decrypt(const char *ncryptsec,
                                       const char *password,
                                       nostr_privkey *privkey)
{
    uint8_t payload[NIP49_PAYLOAD_SIZE];
    uint8_t symmetric_key[32];
    nostr_error_t err;

    if (!ncryptsec || !password || !privkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    if (strlen(password) == 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    err = decode_ncryptsec(ncryptsec, payload);
    if (err != NOSTR_OK) {
        return err;
    }

    if (payload[0] != NIP49_VERSION) {
        secure_wipe(payload, sizeof(payload));
        return NOSTR_ERR_NOT_SUPPORTED;
    }

    uint8_t log_n = payload[1];
    if (log_n < 16 || log_n > 22) {
        secure_wipe(payload, sizeof(payload));
        return NOSTR_ERR_INVALID_PARAM;
    }

    const uint8_t *p = payload + 2;
    const uint8_t *salt = p; p += NIP49_SALT_SIZE;
    const uint8_t *nonce = p; p += NIP49_NONCE_SIZE;
    uint8_t key_security = *p++;
    const uint8_t *ciphertext = p; p += NIP49_PRIVKEY_SIZE;
    const uint8_t *mac = p;

    if (!derive_key_scrypt(password, salt, log_n, symmetric_key)) {
        secure_wipe(payload, sizeof(payload));
        return NOSTR_ERR_ENCODING;
    }

    if (!xchacha20_poly1305_decrypt(symmetric_key, nonce,
                                     &key_security, 1,
                                     ciphertext, NIP49_PRIVKEY_SIZE,
                                     mac, privkey->data)) {
        secure_wipe(symmetric_key, sizeof(symmetric_key));
        secure_wipe(payload, sizeof(payload));
        secure_wipe(privkey->data, NIP49_PRIVKEY_SIZE);
        return NOSTR_ERR_INVALID_SIGNATURE;
    }

    secure_wipe(symmetric_key, sizeof(symmetric_key));
    secure_wipe(payload, sizeof(payload));
    return NOSTR_OK;
}

nostr_error_t nostr_ncryptsec_validate(const char *ncryptsec)
{
    uint8_t payload[NIP49_PAYLOAD_SIZE];
    nostr_error_t err;

    if (!ncryptsec) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    err = decode_ncryptsec(ncryptsec, payload);
    if (err != NOSTR_OK) {
        return err;
    }

    if (payload[0] != NIP49_VERSION) {
        secure_wipe(payload, sizeof(payload));
        return NOSTR_ERR_NOT_SUPPORTED;
    }

    uint8_t log_n = payload[1];
    if (log_n < 16 || log_n > 22) {
        secure_wipe(payload, sizeof(payload));
        return NOSTR_ERR_INVALID_PARAM;
    }

    uint8_t key_security = payload[2 + NIP49_SALT_SIZE + NIP49_NONCE_SIZE];
    if (key_security > 0x02) {
        secure_wipe(payload, sizeof(payload));
        return NOSTR_ERR_INVALID_PARAM;
    }

    secure_wipe(payload, sizeof(payload));
    return NOSTR_OK;
}

#else

nostr_error_t nostr_ncryptsec_encrypt(const nostr_privkey *privkey,
                                       const char *password,
                                       uint8_t log_n,
                                       char *ncryptsec,
                                       size_t ncryptsec_size)
{
    (void)privkey; (void)password; (void)log_n; (void)ncryptsec; (void)ncryptsec_size;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_ncryptsec_decrypt(const char *ncryptsec,
                                       const char *password,
                                       nostr_privkey *privkey)
{
    (void)ncryptsec; (void)password; (void)privkey;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_ncryptsec_validate(const char *ncryptsec)
{
    (void)ncryptsec;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif
