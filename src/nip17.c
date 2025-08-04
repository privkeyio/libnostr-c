#include "nostr.h"

#ifdef NOSTR_FEATURE_NIP17

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>

#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
#include <noscrypt/noscrypt.h>
extern NCContext* nc_ctx;
#else
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
extern secp256k1_context* secp256k1_ctx;
#endif

#define KIND_SEAL 13
#define KIND_GIFT_WRAP 1059
#define KIND_DM 14
#define KIND_FILE 15

#define TWO_DAYS_SECONDS (2 * 24 * 60 * 60)

extern nostr_error_t nostr_init(void);

static int64_t random_timestamp_past_two_days()
{
    int64_t now = (int64_t)time(NULL);
    uint32_t random_offset;
    
    if (RAND_bytes((unsigned char*)&random_offset, sizeof(random_offset)) != 1) {
        return now;
    }
    
    random_offset %= TWO_DAYS_SECONDS;
    return now - random_offset;
}

nostr_error_t nostr_nip17_create_rumor(nostr_event** rumor, uint16_t kind, const nostr_key* pubkey, 
                                       const char* content, int64_t created_at)
{
    nostr_error_t err;
    
    if (!rumor || !pubkey || !content) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    err = nostr_event_create(rumor);
    if (err != NOSTR_OK) {
        return err;
    }
    
    (*rumor)->kind = kind;
    memcpy(&(*rumor)->pubkey, pubkey, sizeof(nostr_key));
    (*rumor)->created_at = created_at ? created_at : (int64_t)time(NULL);
    
    err = nostr_event_set_content(*rumor, content);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*rumor);
        *rumor = NULL;
        return err;
    }
    
    err = nostr_event_compute_id(*rumor);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*rumor);
        *rumor = NULL;
        return err;
    }
    
    memset((*rumor)->sig, 0, NOSTR_SIG_SIZE);
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip17_create_seal(nostr_event** seal, const nostr_event* rumor,
                                      const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey)
{
    nostr_error_t err;
    char* rumor_json = NULL;
    char* encrypted_rumor = NULL;
    
    if (!seal || !rumor || !sender_privkey || !recipient_pubkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    err = nostr_event_to_json(rumor, &rumor_json);
    if (err != NOSTR_OK) {
        return err;
    }
    
    err = nostr_nip44_encrypt(sender_privkey, recipient_pubkey, rumor_json, strlen(rumor_json), &encrypted_rumor);
    free(rumor_json);
    if (err != NOSTR_OK) {
        return err;
    }
    
    err = nostr_event_create(seal);
    if (err != NOSTR_OK) {
        free(encrypted_rumor);
        return err;
    }
    
    (*seal)->kind = KIND_SEAL;
    (*seal)->created_at = random_timestamp_past_two_days();
    
    /* Derive pubkey from privkey */
#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
    NCSecretKey nc_secret;
    NCPublicKey nc_public;
    
    memcpy(nc_secret.key, sender_privkey->data, NC_SEC_KEY_SIZE);
    
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
    if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey_internal, sender_privkey->data)) {
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
    
    err = nostr_event_compute_id(*seal);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*seal);
        *seal = NULL;
        return err;
    }
    
    err = nostr_event_sign(*seal, sender_privkey);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*seal);
        *seal = NULL;
        return err;
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip17_create_gift_wrap(nostr_event** wrap, const nostr_event* seal,
                                           const nostr_key* recipient_pubkey)
{
    nostr_error_t err;
    nostr_privkey ephemeral_privkey;
    nostr_key ephemeral_pubkey;
    char* seal_json = NULL;
    char* encrypted_seal = NULL;
    const char* p_tag_values[2];
    
    if (!wrap || !seal || !recipient_pubkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    err = nostr_key_generate(&ephemeral_privkey, &ephemeral_pubkey);
    if (err != NOSTR_OK) {
        return err;
    }
    
    err = nostr_event_to_json(seal, &seal_json);
    if (err != NOSTR_OK) {
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        return err;
    }
    
    err = nostr_nip44_encrypt(&ephemeral_privkey, recipient_pubkey, seal_json, strlen(seal_json), &encrypted_seal);
    free(seal_json);
    if (err != NOSTR_OK) {
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        return err;
    }
    
    err = nostr_event_create(wrap);
    if (err != NOSTR_OK) {
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        free(encrypted_seal);
        return err;
    }
    
    (*wrap)->kind = KIND_GIFT_WRAP;
    (*wrap)->created_at = random_timestamp_past_two_days();
    memcpy(&(*wrap)->pubkey, &ephemeral_pubkey, sizeof(nostr_key));
    
    err = nostr_event_set_content(*wrap, encrypted_seal);
    free(encrypted_seal);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*wrap);
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        *wrap = NULL;
        return err;
    }
    
    char pubkey_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&pubkey_hex[i*2], "%02x", recipient_pubkey->data[i]);
    }
    pubkey_hex[64] = '\0';
    
    p_tag_values[0] = "p";
    p_tag_values[1] = pubkey_hex;
    
    err = nostr_event_add_tag(*wrap, p_tag_values, 2);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*wrap);
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        *wrap = NULL;
        return err;
    }
    
    err = nostr_event_compute_id(*wrap);
    if (err != NOSTR_OK) {
        nostr_event_destroy(*wrap);
        secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
        *wrap = NULL;
        return err;
    }
    
    err = nostr_event_sign(*wrap, &ephemeral_privkey);
    secure_wipe(&ephemeral_privkey, sizeof(ephemeral_privkey));
    if (err != NOSTR_OK) {
        nostr_event_destroy(*wrap);
        *wrap = NULL;
        return err;
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip17_send_dm(nostr_event** dm, const char* content,
                                  const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey,
                                  const char* subject, const uint8_t* reply_to, int64_t created_at)
{
    nostr_error_t err;
    nostr_event* rumor = NULL;
    nostr_event* seal = NULL;
    nostr_key sender_pubkey;
    const char* tag_values[3];
    char recipient_hex[65];
    char reply_hex[65];
    
    if (!dm || !content || !sender_privkey || !recipient_pubkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    /* Derive sender pubkey from privkey */
#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
    NCSecretKey nc_secret;
    NCPublicKey nc_public;
    
    memcpy(nc_secret.key, sender_privkey->data, NC_SEC_KEY_SIZE);
    
    if (NCGetPublicKey(nc_ctx, &nc_secret, &nc_public) != NC_SUCCESS) {
        secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
        return NOSTR_ERR_INVALID_KEY;
    }
    
    memcpy(sender_pubkey.data, nc_public.key, NOSTR_PUBKEY_SIZE);
    secure_wipe(nc_secret.key, NC_SEC_KEY_SIZE);
#else
    secp256k1_pubkey pubkey_internal;
    if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey_internal, sender_privkey->data)) {
        return NOSTR_ERR_INVALID_KEY;
    }
    
    secp256k1_xonly_pubkey xonly_pubkey;
    int parity;
    if (!secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &xonly_pubkey, &parity, &pubkey_internal)) {
        return NOSTR_ERR_INVALID_KEY;
    }
    
    if (!secp256k1_xonly_pubkey_serialize(secp256k1_ctx, sender_pubkey.data, &xonly_pubkey)) {
        return NOSTR_ERR_INVALID_KEY;
    }
#endif
    
    err = nostr_nip17_create_rumor(&rumor, KIND_DM, &sender_pubkey, content, created_at);
    if (err != NOSTR_OK) {
        return err;
    }
    
    for (int i = 0; i < 32; i++) {
        sprintf(&recipient_hex[i*2], "%02x", recipient_pubkey->data[i]);
    }
    recipient_hex[64] = '\0';
    
    tag_values[0] = "p";
    tag_values[1] = recipient_hex;
    err = nostr_event_add_tag(rumor, tag_values, 2);
    if (err != NOSTR_OK) {
        nostr_event_destroy(rumor);
        return err;
    }
    
    if (subject) {
        tag_values[0] = "subject";
        tag_values[1] = subject;
        err = nostr_event_add_tag(rumor, tag_values, 2);
        if (err != NOSTR_OK) {
            nostr_event_destroy(rumor);
            return err;
        }
    }
    
    if (reply_to) {
        for (int i = 0; i < 32; i++) {
            sprintf(&reply_hex[i*2], "%02x", reply_to[i]);
        }
        reply_hex[64] = '\0';
        
        tag_values[0] = "e";
        tag_values[1] = reply_hex;
        err = nostr_event_add_tag(rumor, tag_values, 2);
        if (err != NOSTR_OK) {
            nostr_event_destroy(rumor);
            return err;
        }
    }
    
    err = nostr_nip17_create_seal(&seal, rumor, sender_privkey, recipient_pubkey);
    nostr_event_destroy(rumor);
    if (err != NOSTR_OK) {
        return err;
    }
    
    err = nostr_nip17_create_gift_wrap(dm, seal, recipient_pubkey);
    nostr_event_destroy(seal);
    
    return err;
}

nostr_error_t nostr_nip17_unwrap_dm(const nostr_event* wrap, const nostr_privkey* recipient_privkey,
                                    nostr_event** rumor, nostr_key* sender_pubkey)
{
    nostr_error_t err;
    char* decrypted_seal_json = NULL;
    size_t decrypted_seal_len;
    nostr_event* seal = NULL;
    char* decrypted_rumor_json = NULL;
    size_t decrypted_rumor_len;
    
    if (!wrap || !recipient_privkey || !rumor) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (wrap->kind != KIND_GIFT_WRAP) {
        return NOSTR_ERR_INVALID_EVENT;
    }
    
    err = nostr_nip44_decrypt(recipient_privkey, &wrap->pubkey, wrap->content, 
                             &decrypted_seal_json, &decrypted_seal_len);
    if (err != NOSTR_OK) {
        return err;
    }
    
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
    
    err = nostr_event_verify(seal);
    if (err != NOSTR_OK) {
        nostr_event_destroy(seal);
        return err;
    }
    
    if (sender_pubkey) {
        memcpy(sender_pubkey, &seal->pubkey, sizeof(nostr_key));
    }
    
    err = nostr_nip44_decrypt(recipient_privkey, &seal->pubkey, seal->content,
                             &decrypted_rumor_json, &decrypted_rumor_len);
    nostr_event_destroy(seal);
    if (err != NOSTR_OK) {
        return err;
    }
    
    err = nostr_event_from_json(decrypted_rumor_json, rumor);
    secure_wipe(decrypted_rumor_json, decrypted_rumor_len);
    free(decrypted_rumor_json);
    if (err != NOSTR_OK) {
        return err;
    }
    
    if (memcmp(&(*rumor)->pubkey, sender_pubkey ? sender_pubkey : &seal->pubkey, sizeof(nostr_key)) != 0) {
        nostr_event_destroy(*rumor);
        *rumor = NULL;
        return NOSTR_ERR_INVALID_EVENT;
    }
    
    return NOSTR_OK;
}

#else

/* NIP-17 functionality not available */
nostr_error_t nostr_nip17_send_dm(const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey, const char* message, const char** relays, size_t relay_count, nostr_event** gift_wrap) {
    (void)sender_privkey; (void)recipient_pubkey; (void)message; (void)relays; (void)relay_count; (void)gift_wrap;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nip17_unwrap_dm(const nostr_event* gift_wrap, const nostr_privkey* recipient_privkey, char** message, nostr_key* sender_pubkey) {
    (void)gift_wrap; (void)recipient_privkey; (void)message; (void)sender_pubkey;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif /* NOSTR_FEATURE_NIP17 */
