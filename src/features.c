#include "nostr_features.h"
#include <string.h>

int nostr_feature_nip_supported(int nip_number)
{
    switch (nip_number) {
#ifdef NOSTR_FEATURE_NIP04
        case 4:
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
    static char feature_list[512] = "std,events,keys";
    static int initialized = 0;
    
    if (!initialized) {
        
#ifdef NOSTR_FEATURE_ENCODING
        strcat(feature_list, ",encoding");
#endif
#ifdef NOSTR_FEATURE_NIP04
        strcat(feature_list, ",nip04");
#endif
#ifdef NOSTR_FEATURE_NIP13
        strcat(feature_list, ",nip13");
#endif
#ifdef NOSTR_FEATURE_NIP17
        strcat(feature_list, ",nip17");
#endif
#ifdef NOSTR_FEATURE_NIP44
        strcat(feature_list, ",nip44");
#endif
#ifdef NOSTR_FEATURE_NIP46
        strcat(feature_list, ",nip46");
#endif
#ifdef NOSTR_FEATURE_NIP47
        strcat(feature_list, ",nip47");
#endif
#ifdef NOSTR_FEATURE_NIP57
        strcat(feature_list, ",nip57");
#endif
#ifdef NOSTR_FEATURE_NIP59
        strcat(feature_list, ",nip59");
#endif
#ifdef NOSTR_FEATURE_RELAY
        strcat(feature_list, ",relay");
#endif
#ifdef NOSTR_FEATURE_RELAY_PROTOCOL
        strcat(feature_list, ",relay-protocol");
#endif
#ifdef NOSTR_FEATURE_HD_KEYS
        strcat(feature_list, ",hd-keys");
#endif
#ifdef NOSTR_FEATURE_JSON_ENHANCED
        strcat(feature_list, ",json-enhanced");
#endif
#ifdef NOSTR_FEATURE_THREADING
        strcat(feature_list, ",threading");
#endif
        
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