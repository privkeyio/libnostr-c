#include "nostr.h"

#ifdef NOSTR_FEATURE_NIP26

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#ifdef HAVE_MBEDTLS
#include <mbedtls/sha256.h>
#else
#include <openssl/sha.h>
#endif

#ifdef HAVE_NOSCRYPT
#include <noscrypt.h>
extern NCContext* nc_ctx;
#endif

#ifdef HAVE_SECP256K1
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
extern secp256k1_context* secp256k1_ctx;
#endif

extern nostr_error_t nostr_init(void);
extern int nostr_random_bytes(uint8_t *buf, size_t len);

static void nip26_sha256(const uint8_t *data, size_t len, uint8_t *hash)
{
#ifdef HAVE_MBEDTLS
    mbedtls_sha256(data, len, hash, 0);
#else
    SHA256(data, len, hash);
#endif
}

static int is_valid_hex(const char *str, size_t expected_len)
{
    if (!str || strlen(str) != expected_len)
        return 0;
    for (size_t i = 0; i < expected_len; i++) {
        if (!isxdigit((unsigned char)str[i]))
            return 0;
    }
    return 1;
}

#define NIP26_MAX_CONDITIONS 100
#define NIP26_MAX_KINDS 256
#define NIP26_MAX_CONDITIONS_LEN 4096

static void cleanup_conditions(nostr_delegation_conditions *out)
{
    free(out->kinds);
    out->kinds = NULL;
    out->kind_count = 0;
}

static int parse_delegation_conditions(const char *conditions, nostr_delegation_conditions *out)
{
    if (!conditions || !out)
        return 0;

    if (*conditions == '\0')
        return 0;

    memset(out, 0, sizeof(*out));

    const char *p = conditions;
    size_t iterations = 0;

    while (*p) {
        if (++iterations > NIP26_MAX_CONDITIONS) {
            cleanup_conditions(out);
            return 0;
        }

        while (*p == '&')
            p++;

        if (*p == '\0')
            break;

        if (strncmp(p, "kind=", 5) == 0) {
            p += 5;
            char *endptr;
            errno = 0;
            unsigned long val = strtoul(p, &endptr, 10);
            if (errno != 0 || endptr == p || val > UINT16_MAX) {
                cleanup_conditions(out);
                return 0;
            }

            if (out->kind_count >= NIP26_MAX_KINDS) {
                cleanup_conditions(out);
                return 0;
            }

            uint16_t *new_kinds = realloc(out->kinds, sizeof(uint16_t) * (out->kind_count + 1));
            if (!new_kinds) {
                cleanup_conditions(out);
                return 0;
            }
            out->kinds = new_kinds;
            out->kinds[out->kind_count++] = (uint16_t)val;
            p = endptr;
        }
        else if (strncmp(p, "created_at>", 11) == 0) {
            p += 11;
            char *endptr;
            errno = 0;
            long long val = strtoll(p, &endptr, 10);
            if (errno != 0 || endptr == p) {
                cleanup_conditions(out);
                return 0;
            }
            out->created_after = (int64_t)val;
            out->has_created_after = 1;
            p = endptr;
        }
        else if (strncmp(p, "created_at<", 11) == 0) {
            p += 11;
            char *endptr;
            errno = 0;
            long long val = strtoll(p, &endptr, 10);
            if (errno != 0 || endptr == p) {
                cleanup_conditions(out);
                return 0;
            }
            out->created_before = (int64_t)val;
            out->has_created_before = 1;
            p = endptr;
        }
        else {
            cleanup_conditions(out);
            return 0;
        }
    }

    return 1;
}

static nostr_error_t build_delegation_hash(const nostr_key *delegatee_pubkey,
                                            const char *conditions,
                                            uint8_t hash[32])
{
    size_t conditions_len = strlen(conditions);
    if (conditions_len > NIP26_MAX_CONDITIONS_LEN)
        return NOSTR_ERR_INVALID_PARAM;
    if (conditions_len > SIZE_MAX - 84)
        return NOSTR_ERR_INVALID_PARAM;

    char delegatee_hex[65];
    nostr_hex_encode(delegatee_pubkey->data, 32, delegatee_hex);

    size_t delegation_str_len = 17 + 64 + 1 + conditions_len + 1;
    char *delegation_string = malloc(delegation_str_len);
    if (!delegation_string)
        return NOSTR_ERR_MEMORY;

    snprintf(delegation_string, delegation_str_len, "nostr:delegation:%s:%s",
             delegatee_hex, conditions);

    nip26_sha256((const uint8_t *)delegation_string, strlen(delegation_string), hash);
    free(delegation_string);

    return NOSTR_OK;
}

nostr_error_t nostr_delegation_create(const nostr_privkey *delegator_privkey,
                                      const nostr_key *delegatee_pubkey,
                                      const char *conditions,
                                      nostr_delegation *delegation)
{
    if (!delegator_privkey || !delegatee_pubkey || !conditions || !delegation)
        return NOSTR_ERR_INVALID_PARAM;

#if !defined(HAVE_NOSCRYPT) && !defined(HAVE_SECP256K1)
    return NOSTR_ERR_NOT_SUPPORTED;
#endif

    nostr_error_t err = nostr_init();
    if (err != NOSTR_OK)
        return err;

    memset(delegation, 0, sizeof(*delegation));

    uint8_t hash[32];
    err = build_delegation_hash(delegatee_pubkey, conditions, hash);
    if (err != NOSTR_OK)
        return err;

#ifdef HAVE_NOSCRYPT
    NCSecretKey nc_secret;
    NCPublicKey nc_public;

    memcpy(nc_secret.key, delegator_privkey->data, 32);

    if (NCGetPublicKey(nc_ctx, &nc_secret, &nc_public) != NC_SUCCESS) {
        secure_wipe(nc_secret.key, 32);
        return NOSTR_ERR_INVALID_KEY;
    }

    memcpy(delegation->delegator_pubkey.data, nc_public.key, 32);

    uint8_t random32[32];
    if (nostr_random_bytes(random32, 32) != 1) {
        secure_wipe(nc_secret.key, 32);
        return NOSTR_ERR_MEMORY;
    }

    if (NCSignDigest(nc_ctx, &nc_secret, random32, hash, delegation->token) != NC_SUCCESS) {
        secure_wipe(nc_secret.key, 32);
        return NOSTR_ERR_INVALID_SIGNATURE;
    }

    secure_wipe(nc_secret.key, 32);
    secure_wipe(random32, 32);

#elif defined(HAVE_SECP256K1)
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(secp256k1_ctx, &keypair, delegator_privkey->data))
        return NOSTR_ERR_INVALID_KEY;

    secp256k1_xonly_pubkey xonly_pubkey;
    if (!secp256k1_keypair_xonly_pub(secp256k1_ctx, &xonly_pubkey, NULL, &keypair)) {
        secure_wipe(&keypair, sizeof(keypair));
        return NOSTR_ERR_INVALID_KEY;
    }

    if (!secp256k1_xonly_pubkey_serialize(secp256k1_ctx, delegation->delegator_pubkey.data, &xonly_pubkey)) {
        secure_wipe(&keypair, sizeof(keypair));
        return NOSTR_ERR_INVALID_KEY;
    }

    uint8_t aux_rand[32];
    if (nostr_random_bytes(aux_rand, 32) != 1) {
        secure_wipe(&keypair, sizeof(keypair));
        return NOSTR_ERR_MEMORY;
    }

    if (!secp256k1_schnorrsig_sign32(secp256k1_ctx, delegation->token, hash, &keypair, aux_rand)) {
        secure_wipe(&keypair, sizeof(keypair));
        secure_wipe(aux_rand, 32);
        return NOSTR_ERR_INVALID_SIGNATURE;
    }

    secure_wipe(&keypair, sizeof(keypair));
    secure_wipe(aux_rand, 32);
#endif

    delegation->conditions = strdup(conditions);
    if (!delegation->conditions) {
        secure_wipe(delegation, sizeof(*delegation));
        return NOSTR_ERR_MEMORY;
    }

    if (!parse_delegation_conditions(conditions, &delegation->parsed_conditions)) {
        free(delegation->conditions);
        secure_wipe(delegation, sizeof(*delegation));
        return NOSTR_ERR_INVALID_PARAM;
    }

    return NOSTR_OK;
}

nostr_error_t nostr_delegation_verify(const nostr_delegation *delegation,
                                      const nostr_key *delegatee_pubkey)
{
    if (!delegation || !delegatee_pubkey || !delegation->conditions)
        return NOSTR_ERR_INVALID_PARAM;

#if !defined(HAVE_NOSCRYPT) && !defined(HAVE_SECP256K1)
    return NOSTR_ERR_NOT_SUPPORTED;
#endif

    nostr_error_t err = nostr_init();
    if (err != NOSTR_OK)
        return err;

    uint8_t hash[32];
    err = build_delegation_hash(delegatee_pubkey, delegation->conditions, hash);
    if (err != NOSTR_OK)
        return err;

#ifdef HAVE_NOSCRYPT
    NCPublicKey nc_public;
    memcpy(nc_public.key, delegation->delegator_pubkey.data, 32);

    if (NCVerifyDigest(nc_ctx, &nc_public, hash, delegation->token) != NC_SUCCESS)
        return NOSTR_ERR_INVALID_SIGNATURE;

#elif defined(HAVE_SECP256K1)
    secp256k1_xonly_pubkey xonly_pubkey;
    if (!secp256k1_xonly_pubkey_parse(secp256k1_ctx, &xonly_pubkey, delegation->delegator_pubkey.data))
        return NOSTR_ERR_INVALID_KEY;

    if (!secp256k1_schnorrsig_verify(secp256k1_ctx, delegation->token, hash, 32, &xonly_pubkey))
        return NOSTR_ERR_INVALID_SIGNATURE;
#endif

    return NOSTR_OK;
}

nostr_error_t nostr_delegation_check_conditions(const nostr_delegation *delegation,
                                                uint16_t event_kind,
                                                int64_t created_at)
{
    if (!delegation)
        return NOSTR_ERR_INVALID_PARAM;

    const nostr_delegation_conditions *cond = &delegation->parsed_conditions;

    if (cond->kind_count > 0) {
        int found = 0;
        for (size_t i = 0; i < cond->kind_count; i++) {
            if (cond->kinds[i] == event_kind) {
                found = 1;
                break;
            }
        }
        if (!found)
            return NOSTR_ERR_INVALID_EVENT;
    }

    if (cond->has_created_after && created_at <= cond->created_after)
        return NOSTR_ERR_INVALID_EVENT;

    if (cond->has_created_before && created_at >= cond->created_before)
        return NOSTR_ERR_INVALID_EVENT;

    return NOSTR_OK;
}

nostr_error_t nostr_event_add_delegation(nostr_event *event,
                                         const nostr_delegation *delegation)
{
    if (!event || !delegation || !delegation->conditions)
        return NOSTR_ERR_INVALID_PARAM;

    char delegator_hex[65];
    nostr_hex_encode(delegation->delegator_pubkey.data, 32, delegator_hex);

    char token_hex[129];
    nostr_hex_encode(delegation->token, 64, token_hex);

    const char *tag_values[4] = {
        "delegation",
        delegator_hex,
        delegation->conditions,
        token_hex
    };

    return nostr_event_add_tag(event, tag_values, 4);
}

nostr_error_t nostr_event_get_delegation(const nostr_event *event,
                                         nostr_delegation *delegation)
{
    if (!event || !delegation)
        return NOSTR_ERR_INVALID_PARAM;

    memset(delegation, 0, sizeof(*delegation));

    for (size_t i = 0; i < event->tags_count; i++) {
        const nostr_tag *tag = &event->tags[i];
        if (tag->count >= 4 && tag->values && tag->values[0] &&
            strcmp(tag->values[0], "delegation") == 0) {

            const char *delegator_hex = tag->values[1];
            const char *conditions = tag->values[2];
            const char *token_hex = tag->values[3];

            if (!delegator_hex || !conditions || !token_hex)
                return NOSTR_ERR_INVALID_EVENT;

            size_t conditions_len = strlen(conditions);
            if (conditions_len == 0 || conditions_len > NIP26_MAX_CONDITIONS_LEN)
                return NOSTR_ERR_INVALID_EVENT;

            if (!is_valid_hex(delegator_hex, 64))
                return NOSTR_ERR_INVALID_EVENT;

            if (!is_valid_hex(token_hex, 128))
                return NOSTR_ERR_INVALID_EVENT;

            if (strlen(conditions) > NIP26_MAX_CONDITIONS_LEN)
                return NOSTR_ERR_INVALID_EVENT;

            if (nostr_hex_decode(delegator_hex, delegation->delegator_pubkey.data, 32) != 32)
                return NOSTR_ERR_INVALID_EVENT;

            if (nostr_hex_decode(token_hex, delegation->token, 64) != 64)
                return NOSTR_ERR_INVALID_EVENT;

            delegation->conditions = strdup(conditions);
            if (!delegation->conditions)
                return NOSTR_ERR_MEMORY;

            if (!parse_delegation_conditions(conditions, &delegation->parsed_conditions)) {
                free(delegation->conditions);
                delegation->conditions = NULL;
                return NOSTR_ERR_INVALID_EVENT;
            }

            return NOSTR_OK;
        }
    }

    return NOSTR_ERR_NOT_FOUND;
}

nostr_error_t nostr_event_verify_delegation(const nostr_event *event)
{
    if (!event)
        return NOSTR_ERR_INVALID_PARAM;

    nostr_delegation delegation;
    nostr_error_t err = nostr_event_get_delegation(event, &delegation);
    if (err != NOSTR_OK)
        return err;

    err = nostr_delegation_verify(&delegation, &event->pubkey);
    if (err == NOSTR_OK)
        err = nostr_delegation_check_conditions(&delegation, event->kind, event->created_at);

    nostr_delegation_free(&delegation);
    return err;
}

void nostr_delegation_free(nostr_delegation *delegation)
{
    if (!delegation)
        return;

    free(delegation->conditions);
    free(delegation->parsed_conditions.kinds);

    secure_wipe(delegation, sizeof(*delegation));
}

#else

nostr_error_t nostr_delegation_create(const nostr_privkey *delegator_privkey,
                                      const nostr_key *delegatee_pubkey,
                                      const char *conditions,
                                      nostr_delegation *delegation)
{
    (void)delegator_privkey;
    (void)delegatee_pubkey;
    (void)conditions;
    (void)delegation;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_delegation_verify(const nostr_delegation *delegation,
                                      const nostr_key *delegatee_pubkey)
{
    (void)delegation;
    (void)delegatee_pubkey;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_delegation_check_conditions(const nostr_delegation *delegation,
                                                uint16_t event_kind,
                                                int64_t created_at)
{
    (void)delegation;
    (void)event_kind;
    (void)created_at;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_event_add_delegation(nostr_event *event,
                                         const nostr_delegation *delegation)
{
    (void)event;
    (void)delegation;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_event_get_delegation(const nostr_event *event,
                                         nostr_delegation *delegation)
{
    (void)event;
    (void)delegation;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_event_verify_delegation(const nostr_event *event)
{
    (void)event;
    return NOSTR_ERR_NOT_SUPPORTED;
}

void nostr_delegation_free(nostr_delegation *delegation)
{
    (void)delegation;
}

#endif
