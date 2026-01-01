#include "nostr.h"

#ifdef NOSTR_FEATURE_NIP59

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>

#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
#include <noscrypt.h>
extern NCContext* nc_ctx;
#else
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
extern secp256k1_context* secp256k1_ctx;
#endif

#define KIND_SEAL 13
#define KIND_GIFT_WRAP 1059
#define TWO_DAYS_SECONDS (2 * 24 * 60 * 60)

extern nostr_error_t nostr_init(void);

static int64_t randomize_timestamp(int64_t base_time)
{
    uint32_t random_offset;
    
    if (RAND_bytes((unsigned char*)&random_offset, sizeof(random_offset)) != 1) {
        return base_time;
    }
    
    random_offset %= TWO_DAYS_SECONDS;
    return base_time - random_offset;
}

nostr_error_t nostr_nip59_wrap_event(nostr_event** gift_wrap, const nostr_event* event_to_wrap,
                                     const nostr_privkey* author_privkey, const nostr_key* recipient_pubkey)
{
    nostr_error_t err;
    nostr_event* seal = NULL;
    nostr_privkey ephemeral_privkey;
    nostr_key ephemeral_pubkey;
    char* event_json = NULL;
    char* seal_json = NULL;
    char* encrypted_event = NULL;
    char* encrypted_seal = NULL;
    const char* p_tag_values[2];
    char pubkey_hex[65];
    
    if (!gift_wrap || !event_to_wrap || !author_privkey || !recipient_pubkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    /* Step 1: Serialize the event to JSON */
    err = nostr_event_to_json(event_to_wrap, &event_json);
    if (err != NOSTR_OK) {
        return err;
    }
    
    /* Step 2: Create seal event */
    err = nostr_event_create(&seal);
    if (err != NOSTR_OK) {
        free(event_json);
        return err;
    }
    
    seal->kind = KIND_SEAL;
    seal->created_at = randomize_timestamp(time(NULL));
    
    /* Derive author's pubkey from privkey */
#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
    NCSecretKey nc_secret;
    NCPublicKey nc_public;
    
    memcpy(nc_secret.key, author_privkey->data, NC_SEC_KEY_SIZE);
    
    if (NCGetPublicKey(nc_ctx, &nc_secret, &nc_public) != NC_SUCCESS) {
        nostr_event_destroy(seal);
        free(event_json);
        secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
        return NOSTR_ERR_INVALID_KEY;
    }
    
    memcpy(seal->pubkey.data, nc_public.key, NOSTR_PUBKEY_SIZE);
    secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
#else
    secp256k1_pubkey pubkey_internal;
    if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey_internal, author_privkey->data)) {
        nostr_event_destroy(seal);
        free(event_json);
        return NOSTR_ERR_INVALID_KEY;
    }
    
    secp256k1_xonly_pubkey xonly_pubkey;
    int parity;
    if (!secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &xonly_pubkey, &parity, &pubkey_internal)) {
        nostr_event_destroy(seal);
        free(event_json);
        return NOSTR_ERR_INVALID_KEY;
    }
    
    if (!secp256k1_xonly_pubkey_serialize(secp256k1_ctx, seal->pubkey.data, &xonly_pubkey)) {
        nostr_event_destroy(seal);
        free(event_json);
        return NOSTR_ERR_INVALID_KEY;
    }
#endif
    
    /* Encrypt event content for seal */
    err = nostr_nip44_encrypt(author_privkey, recipient_pubkey, event_json, strlen(event_json), &encrypted_event);
    free(event_json);
    if (err != NOSTR_OK) {
        nostr_event_destroy(seal);
        return err;
    }
    
    err = nostr_event_set_content(seal, encrypted_event);
    free(encrypted_event);
    if (err != NOSTR_OK) {
        nostr_event_destroy(seal);
        return err;
    }
    
    /* Compute ID and sign seal */
    err = nostr_event_compute_id(seal);
    if (err != NOSTR_OK) {
        nostr_event_destroy(seal);
        return err;
    }
    
    err = nostr_event_sign(seal, author_privkey);
    if (err != NOSTR_OK) {
        nostr_event_destroy(seal);
        return err;
    }
    
    /* Step 3: Create gift wrap */
    err = nostr_key_generate(&ephemeral_privkey, &ephemeral_pubkey);
    if (err != NOSTR_OK) {
        nostr_event_destroy(seal);
        return err;
    }
    
    /* Serialize seal to JSON */
    err = nostr_event_to_json(seal, &seal_json);
    if (err != NOSTR_OK) {
        nostr_event_destroy(seal);
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        return err;
    }
    
    /* Encrypt seal for gift wrap */
    err = nostr_nip44_encrypt(&ephemeral_privkey, recipient_pubkey, seal_json, strlen(seal_json), &encrypted_seal);
    free(seal_json);
    nostr_event_destroy(seal);
    if (err != NOSTR_OK) {
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        return err;
    }
    
    /* Create gift wrap event */
    err = nostr_event_create(gift_wrap);
    if (err != NOSTR_OK) {
        free(encrypted_seal);
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        return err;
    }
    
    (*gift_wrap)->kind = KIND_GIFT_WRAP;
    (*gift_wrap)->created_at = randomize_timestamp(time(NULL));
    memcpy(&(*gift_wrap)->pubkey, &ephemeral_pubkey, sizeof(nostr_key));
    
    err = nostr_event_set_content(*gift_wrap, encrypted_seal);
    free(encrypted_seal);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*gift_wrap);
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        *gift_wrap = NULL;
        return err;
    }
    
    /* Add recipient p tag */
    for (int i = 0; i < 32; i++) {
        sprintf(&pubkey_hex[i*2], "%02x", recipient_pubkey->data[i]);
    }
    pubkey_hex[64] = '\0';
    
    p_tag_values[0] = "p";
    p_tag_values[1] = pubkey_hex;
    
    err = nostr_event_add_tag(*gift_wrap, p_tag_values, 2);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*gift_wrap);
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        *gift_wrap = NULL;
        return err;
    }
    
    /* Compute ID and sign with ephemeral key */
    err = nostr_event_compute_id(*gift_wrap);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*gift_wrap);
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        *gift_wrap = NULL;
        return err;
    }
    
    err = nostr_event_sign(*gift_wrap, &ephemeral_privkey);
    secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
    if (err != NOSTR_OK) {
        nostr_event_destroy(*gift_wrap);
        *gift_wrap = NULL;
        return err;
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip59_unwrap_event(const nostr_event* gift_wrap, const nostr_privkey* recipient_privkey,
                                       nostr_event** unwrapped_event, nostr_key* author_pubkey)
{
    nostr_error_t err;
    char* decrypted_seal_json = NULL;
    size_t decrypted_seal_len;
    nostr_event* seal = NULL;
    char* decrypted_event_json = NULL;
    size_t decrypted_event_len;
    
    if (!gift_wrap || !recipient_privkey || !unwrapped_event) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (gift_wrap->kind != KIND_GIFT_WRAP) {
        return NOSTR_ERR_INVALID_EVENT;
    }
    
    /* Decrypt gift wrap to get seal */
    err = nostr_nip44_decrypt(recipient_privkey, &gift_wrap->pubkey, gift_wrap->content, 
                             &decrypted_seal_json, &decrypted_seal_len);
    if (err != NOSTR_OK) {
        return err;
    }
    
    /* Parse seal event */
    err = nostr_event_from_json(decrypted_seal_json, &seal);
    secure_wipe(decrypted_seal_json, decrypted_seal_len);
    free(decrypted_seal_json);
    if (err != NOSTR_OK) {
        return err;
    }
    
    if (seal->kind != KIND_SEAL) {
        nostr_event_destroy(seal);
        return NOSTR_ERR_INVALID_EVENT;
    }
    
    /* Verify seal signature */
    err = nostr_event_verify(seal);
    if (err != NOSTR_OK) {
        nostr_event_destroy(seal);
        return err;
    }
    
    /* Store author pubkey if requested */
    if (author_pubkey) {
        memcpy(author_pubkey, &seal->pubkey, sizeof(nostr_key));
    }
    
    /* Decrypt seal to get original event */
    err = nostr_nip44_decrypt(recipient_privkey, &seal->pubkey, seal->content,
                             &decrypted_event_json, &decrypted_event_len);
    if (err != NOSTR_OK) {
        nostr_event_destroy(seal);
        return err;
    }
    
    /* Parse original event */
    err = nostr_event_from_json(decrypted_event_json, unwrapped_event);
    secure_wipe(decrypted_event_json, decrypted_event_len);
    free(decrypted_event_json);
    nostr_event_destroy(seal);
    
    return err;
}

nostr_error_t nostr_nip59_create_rumor(nostr_event** rumor, uint16_t kind, const nostr_key* pubkey,
                                       const char* content)
{
    nostr_error_t err;
    
    if (!rumor || !pubkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    err = nostr_event_create(rumor);
    if (err != NOSTR_OK) {
        return err;
    }
    
    (*rumor)->kind = kind;
    memcpy(&(*rumor)->pubkey, pubkey, sizeof(nostr_key));
    (*rumor)->created_at = time(NULL);
    
    if (content) {
        err = nostr_event_set_content(*rumor, content);
        if (err != NOSTR_OK) {
            nostr_event_destroy(*rumor);
            *rumor = NULL;
            return err;
        }
    }
    
    /* Compute ID but don't sign */
    err = nostr_event_compute_id(*rumor);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*rumor);
        *rumor = NULL;
        return err;
    }
    
    /* Clear signature to make it a rumor */
    memset((*rumor)->sig, 0, NOSTR_SIG_SIZE);
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip59_create_seal(nostr_event** seal, const nostr_event* rumor,
                                      const nostr_privkey* author_privkey, const nostr_key* recipient_pubkey)
{
    nostr_error_t err;
    char* rumor_json = NULL;
    char* encrypted_rumor = NULL;
    
    if (!seal || !rumor || !author_privkey || !recipient_pubkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    /* Serialize rumor to JSON */
    err = nostr_event_to_json(rumor, &rumor_json);
    if (err != NOSTR_OK) {
        return err;
    }
    
    /* Encrypt rumor */
    err = nostr_nip44_encrypt(author_privkey, recipient_pubkey, rumor_json, strlen(rumor_json), &encrypted_rumor);
    free(rumor_json);
    if (err != NOSTR_OK) {
        return err;
    }
    
    /* Create seal event */
    err = nostr_event_create(seal);
    if (err != NOSTR_OK) {
        free(encrypted_rumor);
        return err;
    }
    
    (*seal)->kind = KIND_SEAL;
    (*seal)->created_at = randomize_timestamp(time(NULL));
    
    /* Derive author pubkey from privkey */
#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
    NCSecretKey nc_secret;
    NCPublicKey nc_public;
    
    memcpy(nc_secret.key, author_privkey->data, NC_SEC_KEY_SIZE);
    
    if (NCGetPublicKey(nc_ctx, &nc_secret, &nc_public) != NC_SUCCESS) {
        nostr_event_destroy(*seal);
        free(encrypted_rumor);
        *seal = NULL;
        secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
        return NOSTR_ERR_INVALID_KEY;
    }
    
    memcpy((*seal)->pubkey.data, nc_public.key, NOSTR_PUBKEY_SIZE);
    secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
#else
    secp256k1_pubkey pubkey_internal;
    if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey_internal, author_privkey->data)) {
        nostr_event_destroy(*seal);
        free(encrypted_rumor);
        *seal = NULL;
        return NOSTR_ERR_INVALID_KEY;
    }
    
    secp256k1_xonly_pubkey xonly_pubkey;
    int parity;
    if (!secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &xonly_pubkey, &parity, &pubkey_internal)) {
        nostr_event_destroy(*seal);
        free(encrypted_rumor);
        *seal = NULL;
        return NOSTR_ERR_INVALID_KEY;
    }
    
    if (!secp256k1_xonly_pubkey_serialize(secp256k1_ctx, (*seal)->pubkey.data, &xonly_pubkey)) {
        nostr_event_destroy(*seal);
        free(encrypted_rumor);
        *seal = NULL;
        return NOSTR_ERR_INVALID_KEY;
    }
#endif
    
    err = nostr_event_set_content(*seal, encrypted_rumor);
    free(encrypted_rumor);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*seal);
        *seal = NULL;
        return err;
    }
    
    /* Compute ID and sign */
    err = nostr_event_compute_id(*seal);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*seal);
        *seal = NULL;
        return err;
    }
    
    err = nostr_event_sign(*seal, author_privkey);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*seal);
        *seal = NULL;
        return err;
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip59_create_gift_wrap(nostr_event** gift_wrap, const nostr_event* seal,
                                           const nostr_key* recipient_pubkey, const char** extra_tags, size_t tags_count)
{
    nostr_error_t err;
    nostr_privkey ephemeral_privkey;
    nostr_key ephemeral_pubkey;
    char* seal_json = NULL;
    char* encrypted_seal = NULL;
    const char* p_tag_values[2];
    char pubkey_hex[65];
    
    if (!gift_wrap || !seal || !recipient_pubkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    /* Generate ephemeral keypair */
    err = nostr_key_generate(&ephemeral_privkey, &ephemeral_pubkey);
    if (err != NOSTR_OK) {
        return err;
    }
    
    /* Serialize seal to JSON */
    err = nostr_event_to_json(seal, &seal_json);
    if (err != NOSTR_OK) {
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        return err;
    }
    
    /* Encrypt seal with ephemeral key */
    err = nostr_nip44_encrypt(&ephemeral_privkey, recipient_pubkey, seal_json, strlen(seal_json), &encrypted_seal);
    free(seal_json);
    if (err != NOSTR_OK) {
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        return err;
    }
    
    /* Create gift wrap event */
    err = nostr_event_create(gift_wrap);
    if (err != NOSTR_OK) {
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        free(encrypted_seal);
        return err;
    }
    
    (*gift_wrap)->kind = KIND_GIFT_WRAP;
    (*gift_wrap)->created_at = randomize_timestamp(time(NULL));
    memcpy(&(*gift_wrap)->pubkey, &ephemeral_pubkey, sizeof(nostr_key));
    
    err = nostr_event_set_content(*gift_wrap, encrypted_seal);
    free(encrypted_seal);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*gift_wrap);
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        *gift_wrap = NULL;
        return err;
    }
    
    /* Add recipient p tag */
    for (int i = 0; i < 32; i++) {
        sprintf(&pubkey_hex[i*2], "%02x", recipient_pubkey->data[i]);
    }
    pubkey_hex[64] = '\0';
    
    p_tag_values[0] = "p";
    p_tag_values[1] = pubkey_hex;
    
    err = nostr_event_add_tag(*gift_wrap, p_tag_values, 2);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*gift_wrap);
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        *gift_wrap = NULL;
        return err;
    }
    
    /* Add any extra tags */
    if (extra_tags && tags_count > 0) {
        for (size_t i = 0; i < tags_count; i += 2) {
            if (i + 1 < tags_count) {
                const char* tag_values[2] = {extra_tags[i], extra_tags[i + 1]};
                err = nostr_event_add_tag(*gift_wrap, tag_values, 2);
                if (err != NOSTR_OK) {
                    nostr_event_destroy(*gift_wrap);
                    secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
                    *gift_wrap = NULL;
                    return err;
                }
            }
        }
    }
    
    /* Compute ID and sign with ephemeral key */
    err = nostr_event_compute_id(*gift_wrap);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*gift_wrap);
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        *gift_wrap = NULL;
        return err;
    }
    
    err = nostr_event_sign(*gift_wrap, &ephemeral_privkey);
    secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
    if (err != NOSTR_OK) {
        nostr_event_destroy(*gift_wrap);
        *gift_wrap = NULL;
        return err;
    }
    
    return NOSTR_OK;
}

#else

/* NIP-59 functionality not available */
nostr_error_t nostr_nip59_wrap_event(const nostr_event* rumor, const nostr_key* recipient_pubkey, nostr_event** gift_wrap) {
    (void)rumor; (void)recipient_pubkey; (void)gift_wrap;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nip59_unwrap_event(const nostr_event* gift_wrap, const nostr_privkey* recipient_privkey, nostr_event** rumor) {
    (void)gift_wrap; (void)recipient_privkey; (void)rumor;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif /* NOSTR_FEATURE_NIP59 */
