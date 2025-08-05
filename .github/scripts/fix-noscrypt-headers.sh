#!/bin/bash
set -euo pipefail

# This script fixes OpenSSL compatibility issues in noscrypt
# by adapting the code to work with both OpenSSL 1.1.x and 3.x

fix_noscrypt_headers() {
    local noscrypt_dir="${1:-.}"
    local openssl_version="${2:-1.1.1}"
    
    echo "Fixing noscrypt for OpenSSL compatibility in: $noscrypt_dir"
    
    # Check if this is OpenSSL 1.1.x (requires compatibility fixes)
    if [[ "$openssl_version" =~ ^1\.1\. ]]; then
        echo "Detected OpenSSL 1.1.x - applying compatibility patches..."
        
        # Check if the problematic file exists
        if [[ -f "$noscrypt_dir/src/providers/openssl-helpers.c" ]]; then
            echo "Patching openssl-helpers.c for OpenSSL 1.1.x compatibility..."
            
            # Create a compatibility patch that adds missing definitions
            cat > "$noscrypt_dir/src/providers/openssl-compat.h" << 'EOF'
#ifndef OPENSSL_COMPAT_H
#define OPENSSL_COMPAT_H

#include <openssl/opensslv.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/* Compatibility layer for OpenSSL 1.1.x */
#if OPENSSL_VERSION_NUMBER < 0x30000000L

/* OpenSSL 3.0 EVP_MAC API is not available in 1.1.x, use HMAC instead */
#define EVP_MAC_CTX         HMAC_CTX
#define EVP_MAC             void

/* OSSL_PARAM structure for OpenSSL 1.1.x compatibility */
typedef struct {
    const char *key;
    unsigned int data_type;
    void *data;
    size_t data_size;
    size_t return_size;
} OSSL_PARAM;

/* Map newer functions to older equivalents */
#define EVP_MAC_CTX_new(mac)        HMAC_CTX_new()
#define EVP_MAC_CTX_free(ctx)       HMAC_CTX_free(ctx)
#define EVP_MAC_init(ctx, key, keylen, params)  HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL)
#define EVP_MAC_update(ctx, data, len)          HMAC_Update(ctx, data, len)
#define EVP_MAC_final(ctx, out, outlen, size)   HMAC_Final(ctx, out, (unsigned int*)outlen)

/* These functions don't exist in 1.1.x, provide stubs */
#define EVP_MAC_fetch(ctx, name, props)     ((void*)1)  /* Return non-NULL */
#define EVP_MAC_free(mac)                   /* No-op */
#define EVP_MD_fetch(ctx, name, props)      EVP_get_digestbyname(name)
#define EVP_MD_free(md)                     /* No-op */
#define EVP_CIPHER_fetch(ctx, name, props)  EVP_get_cipherbyname(name)
#define EVP_CIPHER_free(cipher)             /* No-op */

/* Use older initialization function */
#define EVP_EncryptInit_ex2(ctx, cipher, key, iv, params) \
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)

/* OSSL_PARAM constructor functions for 1.1.x */
static inline OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf, size_t bsize) {
    OSSL_PARAM param = {key, 4 /* OSSL_PARAM_UTF8_STRING */, buf, bsize, 0};
    return param;
}

static inline OSSL_PARAM OSSL_PARAM_construct_end(void) {
    OSSL_PARAM param = {NULL, 0, NULL, 0, 0};
    return param;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

#endif /* OPENSSL_COMPAT_H */
EOF
            
            # Inject the compatibility header at the very beginning of openssl-helpers.c
            cp "$noscrypt_dir/src/providers/openssl-helpers.c" "$noscrypt_dir/src/providers/openssl-helpers.c.bak"
            
            # Add compatibility header as the first include
            {
                echo '#include "openssl-compat.h"'
                echo ''
                cat "$noscrypt_dir/src/providers/openssl-helpers.c.bak"
            } > "$noscrypt_dir/src/providers/openssl-helpers.c"
            
            rm -f "$noscrypt_dir/src/providers/openssl-helpers.c.bak"
            echo "Patched openssl-helpers.c"
        fi
        
        # Remove vendored headers if they exist to avoid conflicts
        if [[ -d "$noscrypt_dir/vendor/openssl" ]]; then
            echo "Removing vendored OpenSSL headers..."
            rm -rf "$noscrypt_dir/vendor/openssl"
            mkdir -p "$noscrypt_dir/vendor/openssl"
        fi
    else
        echo "OpenSSL 3.x detected - no compatibility patches needed"
        
        # For OpenSSL 3.x, just ensure vendored headers don't conflict
        if [[ -d "$noscrypt_dir/vendor/openssl" ]]; then
            echo "Checking vendored headers..."
            # You might want to keep them for 3.x or remove based on your needs
        fi
    fi
    
    echo "Header fix completed successfully"
}

# Main execution
main() {
    local noscrypt_dir="${1:-.}"
    local openssl_version="${2:-1.1.1}"
    
    if [[ ! -d "$noscrypt_dir" ]]; then
        echo "Error: Directory not found: $noscrypt_dir" >&2
        exit 1
    fi
    
    fix_noscrypt_headers "$noscrypt_dir" "$openssl_version"
}

# Enable debug mode if DEBUG is set
if [[ "${DEBUG:-0}" == "1" ]]; then
    set -x
fi

main "$@"