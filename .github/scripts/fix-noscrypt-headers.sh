#!/bin/bash
set -euo pipefail

# This script fixes OpenSSL header compatibility issues in noscrypt
# by removing conflicting vendored headers and using system headers instead

fix_noscrypt_headers() {
    local noscrypt_dir="${1:-.}"
    local openssl_version="${2:-1.1.1}"
    
    echo "Fixing noscrypt headers in: $noscrypt_dir"
    
    # Check if vendor/openssl directory exists
    if [[ ! -d "$noscrypt_dir/vendor/openssl" ]]; then
        echo "Warning: vendor/openssl directory not found, skipping header fix"
        return 0
    fi
    
    # Remove the problematic vendored OpenSSL headers
    echo "Removing vendored OpenSSL headers..."
    rm -rf "$noscrypt_dir/vendor/openssl"
    
    # Create empty directory to satisfy include paths
    mkdir -p "$noscrypt_dir/vendor/openssl"
    
    # Create a minimal compatibility header that redirects to system headers
    cat > "$noscrypt_dir/vendor/openssl/openssl_redirect.h" << 'EOF'
#ifndef OPENSSL_REDIRECT_H
#define OPENSSL_REDIRECT_H

/* Redirect to system OpenSSL headers */
#include_next <openssl/crypto.h>
#include_next <openssl/evp.h>
#include_next <openssl/hmac.h>
#include_next <openssl/rand.h>

#endif
EOF

    # Patch source files to remove vendor/openssl includes if necessary
    echo "Patching source files..."
    
    # Find all C source files and header files
    find "$noscrypt_dir/src" -type f \( -name "*.c" -o -name "*.h" \) | while read -r file; do
        # Create backup
        cp "$file" "$file.bak"
        
        # Replace vendor/openssl includes with system includes
        sed -i.tmp 's|#include ".*vendor/openssl/\([^"]*\)"|#include <openssl/\1>|g' "$file"
        sed -i.tmp 's|#include <.*vendor/openssl/\([^>]*\)>|#include <openssl/\1>|g' "$file"
        
        # Remove the temporary file created by sed on macOS
        rm -f "$file.tmp"
        
        # Check if file was modified
        if ! diff -q "$file" "$file.bak" > /dev/null; then
            echo "Patched: $file"
        fi
        
        # Remove backup
        rm -f "$file.bak"
    done
    
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