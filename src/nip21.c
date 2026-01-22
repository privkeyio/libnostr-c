#include "nostr.h"

#ifdef NOSTR_FEATURE_ENCODING

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define TLV_SPECIAL 0
#define TLV_RELAY   1
#define TLV_AUTHOR  2
#define TLV_KIND    3

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const uint32_t GENERATOR[] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

static uint32_t bech32_polymod(const uint8_t* values, size_t len) {
    uint32_t chk = 1;
    for (size_t i = 0; i < len; i++) {
        uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ values[i];
        for (int j = 0; j < 5; j++) {
            chk ^= ((top >> j) & 1) ? GENERATOR[j] : 0;
        }
    }
    return chk;
}

static int bech32_hrp_expand(const char* hrp, uint8_t* ret, size_t ret_size) {
    size_t hrp_len = strlen(hrp);
    size_t expanded_len = hrp_len * 2 + 1;
    if (expanded_len > ret_size) return -1;

    for (size_t i = 0; i < hrp_len; i++) {
        ret[i] = hrp[i] >> 5;
        ret[hrp_len + 1 + i] = hrp[i] & 31;
    }
    ret[hrp_len] = 0;

    return (int)expanded_len;
}

static int bech32_verify_checksum(const char* hrp, const uint8_t* data, size_t data_len) {
    uint8_t hrp_expanded[84];
    int hrp_len = bech32_hrp_expand(hrp, hrp_expanded, sizeof(hrp_expanded));
    if (hrp_len < 0) return 0;

    uint8_t* combined = malloc(hrp_len + data_len);
    if (!combined) return 0;

    memcpy(combined, hrp_expanded, hrp_len);
    memcpy(combined + hrp_len, data, data_len);

    int result = bech32_polymod(combined, hrp_len + data_len) == 1;
    free(combined);
    return result;
}

static int bech32_create_checksum(const char* hrp, const uint8_t* data, size_t data_len, uint8_t* checksum) {
    uint8_t hrp_expanded[84];
    int hrp_len = bech32_hrp_expand(hrp, hrp_expanded, sizeof(hrp_expanded));
    if (hrp_len < 0) return 0;

    uint8_t* combined = malloc(hrp_len + data_len + 6);
    if (!combined) return 0;

    memcpy(combined, hrp_expanded, hrp_len);
    memcpy(combined + hrp_len, data, data_len);
    memset(combined + hrp_len + data_len, 0, 6);

    uint32_t polymod = bech32_polymod(combined, hrp_len + data_len + 6) ^ 1;
    for (int i = 0; i < 6; i++) {
        checksum[i] = (polymod >> (5 * (5 - i))) & 31;
    }
    free(combined);
    return 6;
}

static int convert_bits(const uint8_t* in, size_t inlen, uint8_t* out, size_t outlen, int frombits, int tobits, int pad) {
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

static int charset_decode(char c) {
    for (int i = 0; i < 32; i++) {
        if (CHARSET[i] == c) return i;
    }
    return -1;
}

static nostr_error_t decode_bech32_to_bytes(const char* bech32, const char* expected_hrp,
                                            uint8_t* out, size_t out_size, size_t* out_len) {
    if (!bech32 || !out) return NOSTR_ERR_INVALID_PARAM;

    size_t len = strlen(bech32);
    size_t hrp_len = strlen(expected_hrp);

    if (len < hrp_len + 8 || len > 1024) return NOSTR_ERR_ENCODING;
    if (strncmp(bech32, expected_hrp, hrp_len) != 0 || bech32[hrp_len] != '1') {
        return NOSTR_ERR_ENCODING;
    }

    uint8_t* data = malloc(len);
    if (!data) return NOSTR_ERR_MEMORY;

    size_t data_pos = 0;
    for (size_t i = hrp_len + 1; i < len; i++) {
        int val = charset_decode(bech32[i]);
        if (val == -1) {
            free(data);
            return NOSTR_ERR_ENCODING;
        }
        data[data_pos++] = val;
    }

    if (!bech32_verify_checksum(expected_hrp, data, data_pos)) {
        free(data);
        return NOSTR_ERR_ENCODING;
    }

    int decoded_len = convert_bits(data, data_pos - 6, out, out_size, 5, 8, 0);
    free(data);

    if (decoded_len <= 0) return NOSTR_ERR_ENCODING;
    if (out_len) *out_len = decoded_len;

    return NOSTR_OK;
}

static nostr_error_t encode_bytes_to_bech32(const uint8_t* data, size_t data_len,
                                            const char* hrp, char* out, size_t out_size) {
    if (!data || !hrp || !out) return NOSTR_ERR_INVALID_PARAM;

    size_t hrp_len = strlen(hrp);
    size_t max_conv_len = (data_len * 8 + 4) / 5;

    uint8_t* conv = malloc(max_conv_len);
    if (!conv) return NOSTR_ERR_MEMORY;

    int conv_len = convert_bits(data, data_len, conv, max_conv_len, 8, 5, 1);
    if (conv_len <= 0) {
        free(conv);
        return NOSTR_ERR_ENCODING;
    }

    if (out_size < hrp_len + 1 + conv_len + 6 + 1) {
        free(conv);
        return NOSTR_ERR_INVALID_PARAM;
    }

    uint8_t checksum[6];
    bech32_create_checksum(hrp, conv, conv_len, checksum);

    memcpy(out, hrp, hrp_len);
    out[hrp_len] = '1';

    char* pos = out + hrp_len + 1;
    for (int i = 0; i < conv_len; i++) {
        *pos++ = CHARSET[conv[i]];
    }
    for (int i = 0; i < 6; i++) {
        *pos++ = CHARSET[checksum[i]];
    }
    *pos = '\0';

    free(conv);
    return NOSTR_OK;
}

static nostr_error_t parse_tlv(const uint8_t* data, size_t data_len,
                               uint8_t* special, size_t special_size, size_t* special_len,
                               char** relays, size_t* relay_count, size_t max_relays,
                               uint8_t* author, int* has_author,
                               uint32_t* kind, int* has_kind) {
    size_t pos = 0;
    *relay_count = 0;
    if (has_author) *has_author = 0;
    if (has_kind) *has_kind = 0;

    while (pos + 2 <= data_len) {
        uint8_t type = data[pos++];
        uint8_t len = data[pos++];

        if (pos + len > data_len) return NOSTR_ERR_ENCODING;

        switch (type) {
            case TLV_SPECIAL:
                if (special && special_len) {
                    if (len > special_size) return NOSTR_ERR_ENCODING;
                    memcpy(special, data + pos, len);
                    *special_len = len;
                }
                break;
            case TLV_RELAY:
                if (relays && *relay_count < max_relays) {
                    relays[*relay_count] = malloc(len + 1);
                    if (!relays[*relay_count]) return NOSTR_ERR_MEMORY;
                    memcpy(relays[*relay_count], data + pos, len);
                    relays[*relay_count][len] = '\0';
                    (*relay_count)++;
                }
                break;
            case TLV_AUTHOR:
                if (author && len == 32 && has_author) {
                    memcpy(author, data + pos, 32);
                    *has_author = 1;
                }
                break;
            case TLV_KIND:
                if (kind && len == 4 && has_kind) {
                    *kind = ((uint32_t)data[pos] << 24) |
                            ((uint32_t)data[pos + 1] << 16) |
                            ((uint32_t)data[pos + 2] << 8) |
                            (uint32_t)data[pos + 3];
                    *has_kind = 1;
                }
                break;
        }
        pos += len;
    }

    return NOSTR_OK;
}

static size_t build_tlv(uint8_t* out, size_t out_size,
                        const uint8_t* special, size_t special_len,
                        char* const* relays, size_t relay_count,
                        const uint8_t* author,
                        const uint32_t* kind) {
    size_t pos = 0;

    if (special && special_len > 0) {
        if (special_len > 255) return 0;
        if (pos + 2 + special_len > out_size) return 0;
        out[pos++] = TLV_SPECIAL;
        out[pos++] = (uint8_t)special_len;
        memcpy(out + pos, special, special_len);
        pos += special_len;
    }

    if (relays) {
        for (size_t i = 0; i < relay_count && relays[i]; i++) {
            size_t rlen = strlen(relays[i]);
            if (rlen > 255 || pos + 2 + rlen > out_size) continue;
            out[pos++] = TLV_RELAY;
            out[pos++] = (uint8_t)rlen;
            memcpy(out + pos, relays[i], rlen);
            pos += rlen;
        }
    }

    if (author) {
        if (pos + 2 + 32 > out_size) return 0;
        out[pos++] = TLV_AUTHOR;
        out[pos++] = 32;
        memcpy(out + pos, author, 32);
        pos += 32;
    }

    if (kind) {
        if (pos + 2 + 4 > out_size) return 0;
        out[pos++] = TLV_KIND;
        out[pos++] = 4;
        out[pos++] = (*kind >> 24) & 0xff;
        out[pos++] = (*kind >> 16) & 0xff;
        out[pos++] = (*kind >> 8) & 0xff;
        out[pos++] = *kind & 0xff;
    }

    return pos;
}

nostr_error_t nostr_nprofile_encode(const nostr_nprofile* profile, char* bech32, size_t bech32_size) {
    if (!profile || !bech32) return NOSTR_ERR_INVALID_PARAM;

    uint8_t tlv[4096];
    size_t tlv_len = build_tlv(tlv, sizeof(tlv),
                               profile->pubkey.data, 32,
                               profile->relays, profile->relay_count,
                               NULL, NULL);
    if (tlv_len == 0) return NOSTR_ERR_ENCODING;

    return encode_bytes_to_bech32(tlv, tlv_len, "nprofile", bech32, bech32_size);
}

nostr_error_t nostr_nprofile_decode(const char* bech32, nostr_nprofile* profile) {
    if (!bech32 || !profile) return NOSTR_ERR_INVALID_PARAM;

    memset(profile, 0, sizeof(nostr_nprofile));

    uint8_t data[4096];
    size_t data_len;
    nostr_error_t err = decode_bech32_to_bytes(bech32, "nprofile", data, sizeof(data), &data_len);
    if (err != NOSTR_OK) return err;

    size_t special_len = 0;
    err = parse_tlv(data, data_len,
                    profile->pubkey.data, sizeof(profile->pubkey.data), &special_len,
                    profile->relays, &profile->relay_count, NOSTR_URI_MAX_RELAYS,
                    NULL, NULL, NULL, NULL);

    if (err != NOSTR_OK || special_len != 32) {
        nostr_nprofile_free(profile);
        return err != NOSTR_OK ? err : NOSTR_ERR_ENCODING;
    }

    return NOSTR_OK;
}

static void free_relay_array(char** relays, size_t* count) {
    for (size_t i = 0; i < *count; i++) {
        free(relays[i]);
        relays[i] = NULL;
    }
    *count = 0;
}

void nostr_nprofile_free(nostr_nprofile* profile) {
    if (!profile) return;
    free_relay_array(profile->relays, &profile->relay_count);
}

nostr_error_t nostr_nevent_encode(const nostr_nevent* nevent, char* bech32, size_t bech32_size) {
    if (!nevent || !bech32) return NOSTR_ERR_INVALID_PARAM;

    uint8_t tlv[4096];
    size_t tlv_len = build_tlv(tlv, sizeof(tlv),
                               nevent->id, 32,
                               nevent->relays, nevent->relay_count,
                               nevent->has_author ? nevent->author.data : NULL,
                               nevent->has_kind ? &nevent->kind : NULL);
    if (tlv_len == 0) return NOSTR_ERR_ENCODING;

    return encode_bytes_to_bech32(tlv, tlv_len, "nevent", bech32, bech32_size);
}

nostr_error_t nostr_nevent_decode(const char* bech32, nostr_nevent* nevent) {
    if (!bech32 || !nevent) return NOSTR_ERR_INVALID_PARAM;

    memset(nevent, 0, sizeof(nostr_nevent));

    uint8_t data[4096];
    size_t data_len;
    nostr_error_t err = decode_bech32_to_bytes(bech32, "nevent", data, sizeof(data), &data_len);
    if (err != NOSTR_OK) return err;

    size_t special_len = 0;
    err = parse_tlv(data, data_len,
                    nevent->id, sizeof(nevent->id), &special_len,
                    nevent->relays, &nevent->relay_count, NOSTR_URI_MAX_RELAYS,
                    nevent->author.data, &nevent->has_author,
                    &nevent->kind, &nevent->has_kind);

    if (err != NOSTR_OK || special_len != 32) {
        nostr_nevent_free(nevent);
        return err != NOSTR_OK ? err : NOSTR_ERR_ENCODING;
    }

    return NOSTR_OK;
}

void nostr_nevent_free(nostr_nevent* nevent) {
    if (!nevent) return;
    free_relay_array(nevent->relays, &nevent->relay_count);
}

nostr_error_t nostr_naddr_encode(const nostr_naddr* addr, char* bech32, size_t bech32_size) {
    if (!addr || !bech32) return NOSTR_ERR_INVALID_PARAM;

    uint8_t tlv[4096];
    size_t id_len = strlen(addr->identifier);
    size_t tlv_len = build_tlv(tlv, sizeof(tlv),
                               (const uint8_t*)addr->identifier, id_len,
                               addr->relays, addr->relay_count,
                               addr->pubkey.data, &addr->kind);
    if (tlv_len == 0) return NOSTR_ERR_ENCODING;

    return encode_bytes_to_bech32(tlv, tlv_len, "naddr", bech32, bech32_size);
}

nostr_error_t nostr_naddr_decode(const char* bech32, nostr_naddr* addr) {
    if (!bech32 || !addr) return NOSTR_ERR_INVALID_PARAM;

    memset(addr, 0, sizeof(nostr_naddr));

    uint8_t data[4096];
    size_t data_len;
    nostr_error_t err = decode_bech32_to_bytes(bech32, "naddr", data, sizeof(data), &data_len);
    if (err != NOSTR_OK) return err;

    uint8_t special[NOSTR_URI_MAX_IDENTIFIER_LEN];
    size_t special_len = 0;
    int has_author = 0, has_kind = 0;

    err = parse_tlv(data, data_len,
                    special, sizeof(special), &special_len,
                    addr->relays, &addr->relay_count, NOSTR_URI_MAX_RELAYS,
                    addr->pubkey.data, &has_author,
                    &addr->kind, &has_kind);

    if (err != NOSTR_OK || !has_author || !has_kind || special_len >= NOSTR_URI_MAX_IDENTIFIER_LEN) {
        nostr_naddr_free(addr);
        return err != NOSTR_OK ? err : NOSTR_ERR_ENCODING;
    }

    memcpy(addr->identifier, special, special_len);
    addr->identifier[special_len] = '\0';

    return NOSTR_OK;
}

void nostr_naddr_free(nostr_naddr* addr) {
    if (!addr) return;
    free_relay_array(addr->relays, &addr->relay_count);
}

nostr_error_t nostr_nrelay_encode(const nostr_nrelay* relay, char* bech32, size_t bech32_size) {
    if (!relay || !bech32) return NOSTR_ERR_INVALID_PARAM;

    size_t url_len = strlen(relay->url);
    if (url_len == 0 || url_len >= NOSTR_URI_MAX_RELAY_LEN) return NOSTR_ERR_INVALID_PARAM;

    uint8_t tlv[512];
    tlv[0] = TLV_SPECIAL;
    tlv[1] = url_len;
    memcpy(tlv + 2, relay->url, url_len);

    return encode_bytes_to_bech32(tlv, 2 + url_len, "nrelay", bech32, bech32_size);
}

nostr_error_t nostr_nrelay_decode(const char* bech32, nostr_nrelay* relay) {
    if (!bech32 || !relay) return NOSTR_ERR_INVALID_PARAM;

    memset(relay, 0, sizeof(nostr_nrelay));

    uint8_t data[512];
    size_t data_len;
    nostr_error_t err = decode_bech32_to_bytes(bech32, "nrelay", data, sizeof(data), &data_len);
    if (err != NOSTR_OK) return err;

    uint8_t special[NOSTR_URI_MAX_RELAY_LEN];
    size_t special_len = 0;
    size_t unused_count = 0;

    err = parse_tlv(data, data_len, special, sizeof(special), &special_len, NULL, &unused_count, 0, NULL, NULL, NULL, NULL);
    if (err != NOSTR_OK || special_len == 0 || special_len >= NOSTR_URI_MAX_RELAY_LEN) {
        return err != NOSTR_OK ? err : NOSTR_ERR_ENCODING;
    }

    memcpy(relay->url, special, special_len);
    relay->url[special_len] = '\0';

    return NOSTR_OK;
}

nostr_error_t nostr_uri_parse(const char* uri, nostr_uri* result) {
    if (!uri || !result) return NOSTR_ERR_INVALID_PARAM;

    memset(result, 0, sizeof(nostr_uri));

    if (strncmp(uri, "nostr:", 6) != 0) return NOSTR_ERR_ENCODING;
    const char* entity = uri + 6;

    if (strncmp(entity, "npub1", 5) == 0) {
        result->type = NOSTR_URI_NPUB;
        return nostr_key_from_bech32(entity, &result->data.npub);
    }

    if (strncmp(entity, "nsec1", 5) == 0) {
        result->type = NOSTR_URI_NSEC;
        return nostr_privkey_from_bech32(entity, &result->data.nsec);
    }

    if (strncmp(entity, "note1", 5) == 0) {
        result->type = NOSTR_URI_NOTE;
        return nostr_event_id_from_bech32(entity, result->data.note);
    }

    if (strncmp(entity, "nprofile1", 9) == 0) {
        result->type = NOSTR_URI_NPROFILE;
        return nostr_nprofile_decode(entity, &result->data.nprofile);
    }

    if (strncmp(entity, "nevent1", 7) == 0) {
        result->type = NOSTR_URI_NEVENT;
        return nostr_nevent_decode(entity, &result->data.nevent);
    }

    if (strncmp(entity, "naddr1", 6) == 0) {
        result->type = NOSTR_URI_NADDR;
        return nostr_naddr_decode(entity, &result->data.naddr);
    }

    if (strncmp(entity, "nrelay1", 7) == 0) {
        result->type = NOSTR_URI_NRELAY;
        return nostr_nrelay_decode(entity, &result->data.nrelay);
    }

    return NOSTR_ERR_ENCODING;
}

nostr_error_t nostr_uri_encode(const nostr_uri* uri, char* output, size_t output_size) {
    if (!uri || !output || output_size < 7) return NOSTR_ERR_INVALID_PARAM;

    char bech32[1024];
    nostr_error_t err;

    switch (uri->type) {
        case NOSTR_URI_NPUB:
            err = nostr_key_to_bech32(&uri->data.npub, "npub", bech32, sizeof(bech32));
            break;
        case NOSTR_URI_NSEC:
            err = nostr_privkey_to_bech32(&uri->data.nsec, bech32, sizeof(bech32));
            break;
        case NOSTR_URI_NOTE:
            err = nostr_event_id_to_bech32(uri->data.note, bech32, sizeof(bech32));
            break;
        case NOSTR_URI_NPROFILE:
            err = nostr_nprofile_encode(&uri->data.nprofile, bech32, sizeof(bech32));
            break;
        case NOSTR_URI_NEVENT:
            err = nostr_nevent_encode(&uri->data.nevent, bech32, sizeof(bech32));
            break;
        case NOSTR_URI_NADDR:
            err = nostr_naddr_encode(&uri->data.naddr, bech32, sizeof(bech32));
            break;
        case NOSTR_URI_NRELAY:
            err = nostr_nrelay_encode(&uri->data.nrelay, bech32, sizeof(bech32));
            break;
        default:
            return NOSTR_ERR_INVALID_PARAM;
    }

    if (err != NOSTR_OK) return err;

    size_t bech32_len = strlen(bech32);
    if (output_size < 6 + bech32_len + 1) return NOSTR_ERR_INVALID_PARAM;

    memcpy(output, "nostr:", 6);
    memcpy(output + 6, bech32, bech32_len + 1);

    return NOSTR_OK;
}

void nostr_uri_free(nostr_uri* uri) {
    if (!uri) return;

    switch (uri->type) {
        case NOSTR_URI_NSEC:
            secure_wipe(uri->data.nsec.data, sizeof(uri->data.nsec.data));
            break;
        case NOSTR_URI_NPROFILE:
            nostr_nprofile_free(&uri->data.nprofile);
            break;
        case NOSTR_URI_NEVENT:
            nostr_nevent_free(&uri->data.nevent);
            break;
        case NOSTR_URI_NADDR:
            nostr_naddr_free(&uri->data.naddr);
            break;
        default:
            break;
    }
}

#else

nostr_error_t nostr_uri_parse(const char* uri, nostr_uri* result) {
    (void)uri; (void)result;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_uri_encode(const nostr_uri* uri, char* output, size_t output_size) {
    (void)uri; (void)output; (void)output_size;
    return NOSTR_ERR_NOT_SUPPORTED;
}

void nostr_uri_free(nostr_uri* uri) {
    (void)uri;
}

nostr_error_t nostr_nprofile_encode(const nostr_nprofile* profile, char* bech32, size_t bech32_size) {
    (void)profile; (void)bech32; (void)bech32_size;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nprofile_decode(const char* bech32, nostr_nprofile* profile) {
    (void)bech32; (void)profile;
    return NOSTR_ERR_NOT_SUPPORTED;
}

void nostr_nprofile_free(nostr_nprofile* profile) {
    (void)profile;
}

nostr_error_t nostr_nevent_encode(const nostr_nevent* event, char* bech32, size_t bech32_size) {
    (void)event; (void)bech32; (void)bech32_size;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nevent_decode(const char* bech32, nostr_nevent* nevent) {
    (void)bech32; (void)nevent;
    return NOSTR_ERR_NOT_SUPPORTED;
}

void nostr_nevent_free(nostr_nevent* nevent) {
    (void)nevent;
}

nostr_error_t nostr_naddr_encode(const nostr_naddr* addr, char* bech32, size_t bech32_size) {
    (void)addr; (void)bech32; (void)bech32_size;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_naddr_decode(const char* bech32, nostr_naddr* addr) {
    (void)bech32; (void)addr;
    return NOSTR_ERR_NOT_SUPPORTED;
}

void nostr_naddr_free(nostr_naddr* addr) {
    (void)addr;
}

nostr_error_t nostr_nrelay_encode(const nostr_nrelay* relay, char* bech32, size_t bech32_size) {
    (void)relay; (void)bech32; (void)bech32_size;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nrelay_decode(const char* bech32, nostr_nrelay* relay) {
    (void)bech32; (void)relay;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif
