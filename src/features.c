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
#ifdef NOSTR_FEATURE_NIP05
        case 5:
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
#ifdef NOSTR_FEATURE_NIP49
        case 49:
            return 1;
#endif
#ifdef NOSTR_FEATURE_NIP51
        case 51:
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
#ifdef NOSTR_FEATURE_NIP65
        case 65:
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

#define APPEND_FEATURE(str) do { \
    int n = snprintf(feature_list + pos, remaining, str); \
    if (n > 0 && (size_t)n < remaining) { pos += n; remaining -= n; } \
} while(0)

        APPEND_FEATURE("std,events,keys");
#ifdef NOSTR_FEATURE_ENCODING
        APPEND_FEATURE(",encoding");
#endif
#ifdef NOSTR_FEATURE_NIP04
        APPEND_FEATURE(",nip04");
#endif
#ifdef NOSTR_FEATURE_NIP05
        APPEND_FEATURE(",nip05");
#endif
#ifdef NOSTR_FEATURE_NIP10
        APPEND_FEATURE(",nip10");
#endif
#ifdef NOSTR_FEATURE_NIP13
        APPEND_FEATURE(",nip13");
#endif
#ifdef NOSTR_FEATURE_NIP17
        APPEND_FEATURE(",nip17");
#endif
#ifdef NOSTR_FEATURE_NIP25
        APPEND_FEATURE(",nip25");
#endif
#ifdef NOSTR_FEATURE_NIP44
        APPEND_FEATURE(",nip44");
#endif
#ifdef NOSTR_FEATURE_NIP46
        APPEND_FEATURE(",nip46");
#endif
#ifdef NOSTR_FEATURE_NIP47
        APPEND_FEATURE(",nip47");
#endif
#ifdef NOSTR_FEATURE_NIP49
        APPEND_FEATURE(",nip49");
#endif
#ifdef NOSTR_FEATURE_NIP51
        APPEND_FEATURE(",nip51");
#endif
#ifdef NOSTR_FEATURE_NIP57
        APPEND_FEATURE(",nip57");
#endif
#ifdef NOSTR_FEATURE_NIP59
        APPEND_FEATURE(",nip59");
#endif
#ifdef NOSTR_FEATURE_NIP65
        APPEND_FEATURE(",nip65");
#endif
#ifdef NOSTR_FEATURE_RELAY
        APPEND_FEATURE(",relay");
#endif
#ifdef NOSTR_FEATURE_RELAY_PROTOCOL
        APPEND_FEATURE(",relay-protocol");
#endif
#ifdef NOSTR_FEATURE_HD_KEYS
        APPEND_FEATURE(",hd-keys");
#endif
#ifdef NOSTR_FEATURE_JSON_ENHANCED
        APPEND_FEATURE(",json-enhanced");
#endif
#ifdef NOSTR_FEATURE_THREADING
        APPEND_FEATURE(",threading");
#endif
#undef APPEND_FEATURE

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