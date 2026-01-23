#include "nostr.h"
#include "bech32_internal.h"

#ifdef NOSTR_FEATURE_ENCODING

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

const char BECH32_CHARSET[33] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const uint32_t BECH32_GENERATOR[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

uint32_t bech32_polymod(const uint8_t* values, size_t len) {
    uint32_t chk = 1;
    for (size_t i = 0; i < len; i++) {
        uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ values[i];
        for (int j = 0; j < 5; j++) {
            chk ^= ((top >> j) & 1) ? BECH32_GENERATOR[j] : 0;
        }
    }
    return chk;
}

int bech32_hrp_expand(const char* hrp, uint8_t* ret, size_t ret_size) {
    size_t hrp_len = strlen(hrp);
    if (hrp_len > (SIZE_MAX - 1) / 2) return -1;
    size_t expanded_len = hrp_len * 2 + 1;
    if (expanded_len > ret_size) return -1;

    for (size_t i = 0; i < hrp_len; i++) {
        ret[i] = hrp[i] >> 5;
    }
    ret[hrp_len] = 0;
    for (size_t i = 0; i < hrp_len; i++) {
        ret[hrp_len + 1 + i] = hrp[i] & 31;
    }
    return (int)expanded_len;
}

int bech32_verify_checksum(const char* hrp, const uint8_t* data, size_t data_len) {
    uint8_t hrp_expanded[84];
    int hrp_len = bech32_hrp_expand(hrp, hrp_expanded, sizeof(hrp_expanded));
    if (hrp_len < 0) return 0;

    if ((size_t)hrp_len > SIZE_MAX - data_len) return 0;
    uint8_t* combined = malloc((size_t)hrp_len + data_len);
    if (!combined) return 0;

    memcpy(combined, hrp_expanded, hrp_len);
    memcpy(combined + hrp_len, data, data_len);

    int result = bech32_polymod(combined, (size_t)hrp_len + data_len) == 1;
    free(combined);
    return result;
}

int bech32_create_checksum(const char* hrp, const uint8_t* data, size_t data_len, uint8_t* checksum) {
    uint8_t hrp_expanded[84];
    int hrp_len = bech32_hrp_expand(hrp, hrp_expanded, sizeof(hrp_expanded));
    if (hrp_len < 0) return 0;

    if ((size_t)hrp_len > SIZE_MAX - data_len - 6) return 0;
    uint8_t* combined = malloc((size_t)hrp_len + data_len + 6);
    if (!combined) return 0;

    memcpy(combined, hrp_expanded, hrp_len);
    memcpy(combined + hrp_len, data, data_len);
    memset(combined + hrp_len + data_len, 0, 6);

    uint32_t polymod = bech32_polymod(combined, (size_t)hrp_len + data_len + 6) ^ 1;
    for (int i = 0; i < 6; i++) {
        checksum[i] = (polymod >> (5 * (5 - i))) & 31;
    }
    free(combined);
    return 6;
}

int bech32_convert_bits(const uint8_t* in, size_t inlen, uint8_t* out, size_t outlen, int frombits, int tobits, int pad) {
    uint32_t acc = 0;
    int bits = 0;
    size_t ret = 0;
    uint32_t maxv = (1 << tobits) - 1;
    uint32_t max_acc = (1 << (frombits + tobits - 1)) - 1;
    
    for (size_t i = 0; i < inlen; i++) {
        if (in[i] >> frombits) return 0;
        acc = ((acc << frombits) | in[i]) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            if (ret >= outlen) return 0;
            out[ret++] = (acc >> bits) & maxv;
        }
    }
    
    if (pad) {
        if (bits) {
            if (ret >= outlen) return 0;
            out[ret++] = (acc << (tobits - bits)) & maxv;
        }
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return 0;
    }
    
    return ret;
}

int bech32_charset_decode(char c) {
    for (int i = 0; i < 32; i++) {
        if (BECH32_CHARSET[i] == c) return i;
    }
    return -1;
}

nostr_error_t nostr_key_to_bech32(const nostr_key* key, const char* prefix, char* bech32, size_t bech32_size) {
    if (!key || !prefix || !bech32) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    size_t prefix_len = strlen(prefix);
    if (prefix_len == 0 || bech32_size < prefix_len + 1 + 52 + 6 + 1) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    uint8_t data[52];
    int data_len = bech32_convert_bits(key->data, NOSTR_PUBKEY_SIZE, data, sizeof(data), 8, 5, 1);
    if (data_len <= 0) {
        return NOSTR_ERR_ENCODING;
    }
    
    uint8_t checksum[6];
    if (!bech32_create_checksum(prefix, data, data_len, checksum)) {
        return NOSTR_ERR_ENCODING;
    }

    memcpy(bech32, prefix, prefix_len);
    bech32[prefix_len] = '1';

    char* pos = bech32 + prefix_len + 1;
    for (int i = 0; i < data_len; i++) {
        *pos++ = BECH32_CHARSET[data[i]];
    }
    for (int i = 0; i < 6; i++) {
        *pos++ = BECH32_CHARSET[checksum[i]];
    }
    *pos = '\0';
    
    return NOSTR_OK;
}

nostr_error_t nostr_key_from_bech32(const char* bech32, nostr_key* key) {
    if (!bech32 || !key) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    size_t len = strlen(bech32);
    if (len < 8 || len > 90) {
        return NOSTR_ERR_ENCODING;
    }
    
    int sep = -1;
    for (int i = len - 1; i >= 0; i--) {
        if (bech32[i] == '1') {
            sep = i;
            break;
        }
    }
    
    if (sep == -1 || sep == 0 || sep + 7 > len) {
        return NOSTR_ERR_ENCODING;
    }
    
    char hrp[84];
    if (sep >= sizeof(hrp)) {
        return NOSTR_ERR_ENCODING;
    }
    strncpy(hrp, bech32, sep);
    hrp[sep] = '\0';
    
    uint8_t data[84];
    for (int i = sep + 1; i < len; i++) {
        int val = bech32_charset_decode(bech32[i]);
        if (val == -1) {
            return NOSTR_ERR_ENCODING;
        }
        data[i - sep - 1] = val;
    }
    
    if (!bech32_verify_checksum(hrp, data, len - sep - 1)) {
        return NOSTR_ERR_ENCODING;
    }
    
    uint8_t decoded[32];
    int decoded_len = bech32_convert_bits(data, len - sep - 1 - 6, decoded, sizeof(decoded), 5, 8, 0);
    if (decoded_len != NOSTR_PUBKEY_SIZE) {
        return NOSTR_ERR_ENCODING;
    }
    
    memcpy(key->data, decoded, NOSTR_PUBKEY_SIZE);
    return NOSTR_OK;
}

nostr_error_t nostr_privkey_to_bech32(const nostr_privkey* privkey, char* bech32, size_t bech32_size) {
    if (!privkey || !bech32) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (bech32_size < 64) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    uint8_t data[52];
    int data_len = bech32_convert_bits(privkey->data, NOSTR_PRIVKEY_SIZE, data, sizeof(data), 8, 5, 1);
    if (data_len <= 0) {
        return NOSTR_ERR_ENCODING;
    }
    
    uint8_t checksum[6];
    if (!bech32_create_checksum("nsec", data, data_len, checksum)) {
        return NOSTR_ERR_ENCODING;
    }

    memcpy(bech32, "nsec1", 5);

    char* pos = bech32 + 5;
    for (int i = 0; i < data_len; i++) {
        *pos++ = BECH32_CHARSET[data[i]];
    }
    for (int i = 0; i < 6; i++) {
        *pos++ = BECH32_CHARSET[checksum[i]];
    }
    *pos = '\0';
    
    return NOSTR_OK;
}

nostr_error_t nostr_privkey_from_bech32(const char* bech32, nostr_privkey* privkey) {
    if (!bech32 || !privkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (strncmp(bech32, "nsec1", 5) != 0) {
        return NOSTR_ERR_ENCODING;
    }
    
    size_t len = strlen(bech32);
    if (len < 8 || len > 90) {
        return NOSTR_ERR_ENCODING;
    }
    
    uint8_t data[84];
    for (int i = 5; i < len; i++) {
        int val = bech32_charset_decode(bech32[i]);
        if (val == -1) {
            return NOSTR_ERR_ENCODING;
        }
        data[i - 5] = val;
    }
    
    if (!bech32_verify_checksum("nsec", data, len - 5)) {
        return NOSTR_ERR_ENCODING;
    }
    
    uint8_t decoded[32];
    int decoded_len = bech32_convert_bits(data, len - 5 - 6, decoded, sizeof(decoded), 5, 8, 0);
    if (decoded_len != NOSTR_PRIVKEY_SIZE) {
        return NOSTR_ERR_ENCODING;
    }
    
    memcpy(privkey->data, decoded, NOSTR_PRIVKEY_SIZE);
    return NOSTR_OK;
}

nostr_error_t nostr_event_id_to_bech32(const uint8_t* id, char* bech32, size_t bech32_size) {
    if (!id || !bech32) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (bech32_size < 64) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    uint8_t data[52];
    int data_len = bech32_convert_bits(id, NOSTR_ID_SIZE, data, sizeof(data), 8, 5, 1);
    if (data_len <= 0) {
        return NOSTR_ERR_ENCODING;
    }
    
    uint8_t checksum[6];
    if (!bech32_create_checksum("note", data, data_len, checksum)) {
        return NOSTR_ERR_ENCODING;
    }

    memcpy(bech32, "note1", 5);

    char* pos = bech32 + 5;
    for (int i = 0; i < data_len; i++) {
        *pos++ = BECH32_CHARSET[data[i]];
    }
    for (int i = 0; i < 6; i++) {
        *pos++ = BECH32_CHARSET[checksum[i]];
    }
    *pos = '\0';
    
    return NOSTR_OK;
}

nostr_error_t nostr_event_id_from_bech32(const char* bech32, uint8_t* id) {
    if (!bech32 || !id) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (strncmp(bech32, "note1", 5) != 0) {
        return NOSTR_ERR_ENCODING;
    }
    
    size_t len = strlen(bech32);
    if (len < 8 || len > 90) {
        return NOSTR_ERR_ENCODING;
    }
    
    uint8_t data[84];
    for (int i = 5; i < len; i++) {
        int val = bech32_charset_decode(bech32[i]);
        if (val == -1) {
            return NOSTR_ERR_ENCODING;
        }
        data[i - 5] = val;
    }
    
    if (!bech32_verify_checksum("note", data, len - 5)) {
        return NOSTR_ERR_ENCODING;
    }
    
    uint8_t decoded[32];
    int decoded_len = bech32_convert_bits(data, len - 5 - 6, decoded, sizeof(decoded), 5, 8, 0);
    if (decoded_len != NOSTR_ID_SIZE) {
        return NOSTR_ERR_ENCODING;
    }
    
    memcpy(id, decoded, NOSTR_ID_SIZE);
    return NOSTR_OK;
}

#else

/* Encoding functionality not available */
nostr_error_t nostr_key_to_bech32(const nostr_key* key, const char* hrp, char* output, size_t output_size) {
    (void)key; (void)hrp; (void)output; (void)output_size;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_key_from_bech32(const char* bech32_str, nostr_key* key) {
    (void)bech32_str; (void)key;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif /* NOSTR_FEATURE_ENCODING */
