#!/bin/bash
set -euo pipefail

generate_configuration_h() {
    local output_file="$1"
    
    cat > "$output_file" << 'EOF'
#ifndef OPENSSL_CONFIGURATION_H
#define OPENSSL_CONFIGURATION_H

#define OPENSSL_CONFIGURED_API 0x10100000L

#undef I386_ONLY

#if !defined(OPENSSL_SYS_UEFI)
# define BN_LLONG
# if defined(__LP64__) || defined(_WIN64)
#  define SIXTY_FOUR_BIT_LONG
#  undef SIXTY_FOUR_BIT
#  undef THIRTY_TWO_BIT
#  define BN_ULONG unsigned long
# else
#  undef SIXTY_FOUR_BIT_LONG
#  undef SIXTY_FOUR_BIT
#  define THIRTY_TWO_BIT
#  define BN_ULONG unsigned int
# endif
#endif

#define RC4_INT unsigned int

#endif
EOF
}

generate_opensslv_h() {
    local output_file="$1"
    
    cat > "$output_file" << 'EOF'
#ifndef OPENSSL_OPENSSLV_H
#define OPENSSL_OPENSSLV_H

#define OPENSSL_VERSION_MAJOR  1
#define OPENSSL_VERSION_MINOR  1
#define OPENSSL_VERSION_PATCH  1

#define OPENSSL_VERSION_STR "1.1.1"
#define OPENSSL_FULL_VERSION_STR "1.1.1"
#define OPENSSL_VERSION_TEXT "OpenSSL 1.1.1"

#define OPENSSL_VERSION_NUMBER 0x1010100fL

#endif
EOF
}

main() {
    local noscrypt_dir="${1:-.}"
    local openssl_vendor_dir="$noscrypt_dir/vendor/openssl"
    
    if [[ ! -d "$openssl_vendor_dir" ]]; then
        echo "Error: OpenSSL vendor directory not found: $openssl_vendor_dir" >&2
        exit 1
    fi
    
    generate_configuration_h "$openssl_vendor_dir/configuration.h"
    generate_opensslv_h "$openssl_vendor_dir/opensslv.h"
}

main "$@"