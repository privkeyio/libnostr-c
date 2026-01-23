#include "nostr_features.h"
#include <string.h>
#include <stdio.h>

int nostr_feature_nip_supported(int nip_number)
{
    switch (nip_number) {
#ifdef NOSTR_FEATURE_NIP04
        case 4:
            return 1;
#endif
#ifdef NOSTR_FEATURE_NIP10
        case 10:
            return 1;
#endif
#ifdef NOSTR_FEATURE_NIP13
        case 13:
            return 1;
#endif
#ifdef NOSTR_FEATURE_NIP17
        case 17:
            return 1;
#endif
#ifdef NOSTR_FEATURE_NIP25
        case 25:
            return 1;
#endif
#ifdef NOSTR_FEATURE_NIP44
        case 44:
            return 1;
#endif
#ifdef NOSTR_FEATURE_NIP46
        case 46:
            return 1;
#endif
#ifdef NOSTR_FEATURE_NIP47
        case 47:
            return 1;
#endif
#ifdef NOSTR_FEATURE_NIP57
        case 57:
            return 1;
#endif
#ifdef NOSTR_FEATURE_NIP59
        case 59:
            return 1;
#endif
        default:
            return 0;
    }
}

int nostr_feature_relay_available(void)
{
#ifdef NOSTR_FEATURE_RELAY
    return 1;
#else
    return 0;
#endif
}

int nostr_feature_hd_keys_available(void)
{
#ifdef NOSTR_FEATURE_HD_KEYS
    return 1;
#else
    return 0;
#endif
}

int nostr_feature_json_enhanced_available(void)
{
#ifdef NOSTR_FEATURE_JSON_ENHANCED
    return 1;
#else
    return 0;
#endif
}

int nostr_feature_relay_protocol_available(void)
{
#ifdef NOSTR_FEATURE_RELAY_PROTOCOL
    return 1;
#else
    return 0;
#endif
}

const char* nostr_feature_list_enabled(void)
{
    static char feature_list[512];
    static int initialized = 0;

    if (!initialized) {
        size_t pos = 0;
        size_t remaining = sizeof(feature_list);

        int n = snprintf(feature_list + pos, remaining, "std,events,keys");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }

#ifdef NOSTR_FEATURE_ENCODING
        n = snprintf(feature_list + pos, remaining, ",encoding");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_NIP04
        n = snprintf(feature_list + pos, remaining, ",nip04");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_NIP10
        n = snprintf(feature_list + pos, remaining, ",nip10");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_NIP13
        n = snprintf(feature_list + pos, remaining, ",nip13");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_NIP17
        n = snprintf(feature_list + pos, remaining, ",nip17");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_NIP25
        n = snprintf(feature_list + pos, remaining, ",nip25");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_NIP44
        n = snprintf(feature_list + pos, remaining, ",nip44");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_NIP46
        n = snprintf(feature_list + pos, remaining, ",nip46");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_NIP47
        n = snprintf(feature_list + pos, remaining, ",nip47");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_NIP57
        n = snprintf(feature_list + pos, remaining, ",nip57");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_NIP59
        n = snprintf(feature_list + pos, remaining, ",nip59");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_RELAY
        n = snprintf(feature_list + pos, remaining, ",relay");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_RELAY_PROTOCOL
        n = snprintf(feature_list + pos, remaining, ",relay-protocol");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_HD_KEYS
        n = snprintf(feature_list + pos, remaining, ",hd-keys");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_JSON_ENHANCED
        n = snprintf(feature_list + pos, remaining, ",json-enhanced");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
#ifdef NOSTR_FEATURE_THREADING
        n = snprintf(feature_list + pos, remaining, ",threading");
        if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; }
#endif
        (void)pos;
        (void)remaining;

        initialized = 1;
    }

    return feature_list;
}

const char* nostr_feature_crypto_backend_info(void)
{
#ifdef NOSTR_FEATURE_CRYPTO_NOSCRYPT
    return "noscrypt (preferred)";
#elif defined(NOSTR_FEATURE_CRYPTO_SECP256K1)
#ifdef HAVE_SCHNORRSIG_SIGN32
    return "secp256k1 (with schnorr support)";
#else
    return "secp256k1 (limited - no schnorr)";
#endif
#else
    return "none (error - should not happen)";
#endif
}