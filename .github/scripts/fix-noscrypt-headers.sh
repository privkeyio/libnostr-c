#!/bin/bash
# Production-grade OpenSSL header fix for noscrypt builds
# Version: 1.0.0
# Usage: ./fix-noscrypt-headers.sh <noscrypt_directory> [openssl_version]

set -euo pipefail  # Strict error handling

# Configuration
readonly SCRIPT_VERSION="1.0.0"
readonly DEFAULT_OPENSSL_VERSION="3.0.0"

# Logging functions
log_info() { echo "[INFO] $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }
log_debug() { [[ "${DEBUG:-}" == "1" ]] && echo "[DEBUG] $*" >&2 || true; }

# Validate inputs
validate_inputs() {
    local noscrypt_dir="${1:-}"
    
    if [[ -z "$noscrypt_dir" ]]; then
        log_error "Usage: $0 <noscrypt_directory> [openssl_version]"
        exit 1
    fi
    
    if [[ ! -d "$noscrypt_dir" ]]; then
        log_error "noscrypt directory not found: $noscrypt_dir"
        exit 1
    fi
    
    if [[ ! -d "$noscrypt_dir/vendor/openssl" ]]; then
        log_error "OpenSSL vendor directory not found: $noscrypt_dir/vendor/openssl"
        exit 1
    fi
}

# Generate configuration.h with version-specific settings
generate_configuration_h() {
    local output_file="$1"
    local openssl_version="$2"
    
    # Extract version components
    local major minor patch
    IFS='.' read -r major minor patch <<< "$openssl_version"
    local api_level=$((major * 10000 + minor * 100))
    
    log_debug "Generating configuration.h for OpenSSL $openssl_version (API level: $api_level)"
    
    cat > "$output_file" << EOF
/*
 * WARNING: do not edit!
 * Generated configuration header for OpenSSL compatibility
 * Script version: $SCRIPT_VERSION
 * OpenSSL version: $openssl_version
 * Generated at: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
 */

#ifndef OPENSSL_CONFIGURATION_H
# define OPENSSL_CONFIGURATION_H
# pragma once

# ifdef  __cplusplus
extern "C" {
# endif

# ifdef OPENSSL_ALGORITHM_DEFINES
#  error OPENSSL_ALGORITHM_DEFINES no longer supported
# endif

/*
 * OpenSSL API compatibility level
 * This determines which deprecated functions are available
 */
# define OPENSSL_CONFIGURED_API $api_level

/* Architecture-specific settings */
# undef I386_ONLY

/*
 * Cipher-specific settings (part of public API)
 */
# if !defined(OPENSSL_SYS_UEFI)
#  define BN_LLONG
/* Only one of the following should be defined */
#  if defined(__LP64__) || defined(_WIN64)
#   define SIXTY_FOUR_BIT_LONG
#   undef SIXTY_FOUR_BIT
#   undef THIRTY_TWO_BIT
#  else
#   undef SIXTY_FOUR_BIT_LONG
#   undef SIXTY_FOUR_BIT
#   define THIRTY_TWO_BIT
#  endif
# endif

# define RC4_INT unsigned int

/* Compression algorithm availability */
# if defined(OPENSSL_NO_COMP) || (defined(OPENSSL_NO_BROTLI) && defined(OPENSSL_NO_ZSTD) && defined(OPENSSL_NO_ZLIB))
#  define OPENSSL_NO_COMP_ALG
# else
#  undef  OPENSSL_NO_COMP_ALG
# endif

# ifdef  __cplusplus
}
# endif

#endif /* OPENSSL_CONFIGURATION_H */
EOF
}

# Generate opensslv.h with proper version info
generate_opensslv_h() {
    local output_file="$1"
    local openssl_version="$2"
    
    # Extract version components
    local major minor patch
    IFS='.' read -r major minor patch <<< "$openssl_version"
    
    log_debug "Generating opensslv.h for OpenSSL $openssl_version"
    
    cat > "$output_file" << EOF
/*
 * WARNING: do not edit!
 * Generated version header for OpenSSL compatibility
 * Script version: $SCRIPT_VERSION
 * OpenSSL version: $openssl_version  
 * Generated at: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
 */

#ifndef OPENSSL_OPENSSLV_H
# define OPENSSL_OPENSSLV_H
# pragma once

# ifdef  __cplusplus
extern "C" {
# endif

/*
 * SECTION 1: VERSION DATA
 */
# define OPENSSL_VERSION_MAJOR  $major
# define OPENSSL_VERSION_MINOR  $minor
# define OPENSSL_VERSION_PATCH  $patch

/*
 * Additional version information
 */
# define OPENSSL_VERSION_PRE_RELEASE ""
# define OPENSSL_VERSION_BUILD_METADATA ""

/*
 * SECTION 2: USEFUL MACROS
 */

/* For checking general API compatibility when preprocessing */  
# define OPENSSL_VERSION_PREREQ(maj,min) \\
    ((OPENSSL_VERSION_MAJOR << 16) + OPENSSL_VERSION_MINOR >= ((maj) << 16) + (min))

/*
 * SECTION 3: VERSION STRINGS
 */
# define OPENSSL_VERSION_STR "$openssl_version"
# define OPENSSL_FULL_VERSION_STR "$openssl_version"
# define OPENSSL_VERSION_TEXT "OpenSSL $openssl_version"

/* Legacy version number format: 0xMNN00PPSL */
# ifdef OPENSSL_VERSION_PRE_RELEASE
#  define _OPENSSL_VERSION_PRE_RELEASE 0x0L
# else
#  define _OPENSSL_VERSION_PRE_RELEASE 0xfL
# endif

# define OPENSSL_VERSION_NUMBER \\
    ( (OPENSSL_VERSION_MAJOR<<28) \\
      |(OPENSSL_VERSION_MINOR<<20) \\
      |(OPENSSL_VERSION_PATCH<<4) \\
      |_OPENSSL_VERSION_PRE_RELEASE )

# ifdef  __cplusplus
}
# endif

#endif /* OPENSSL_OPENSSLV_H */
EOF
}

# Verify generated headers
verify_headers() {
    local config_file="$1"
    local version_file="$2"
    
    log_debug "Verifying generated headers..."
    
    # Check files exist and are readable
    [[ -r "$config_file" ]] || { log_error "Cannot read $config_file"; return 1; }
    [[ -r "$version_file" ]] || { log_error "Cannot read $version_file"; return 1; }
    
    # Basic syntax check (look for matching #ifndef/#endif)
    local config_guards version_guards
    config_guards=$(grep -c "^#.*OPENSSL_CONFIGURATION_H" "$config_file" || true)
    version_guards=$(grep -c "^#.*OPENSSL_OPENSSLV_H" "$version_file" || true)
    
    [[ "$config_guards" -ge 2 ]] || { log_error "Invalid header guards in $config_file"; return 1; }
    [[ "$version_guards" -ge 2 ]] || { log_error "Invalid header guards in $version_file"; return 1; }
    
    # Check for required defines
    grep -q "OPENSSL_CONFIGURED_API" "$config_file" || { log_error "Missing OPENSSL_CONFIGURED_API in $config_file"; return 1; }
    grep -q "OPENSSL_VERSION_MAJOR" "$version_file" || { log_error "Missing OPENSSL_VERSION_MAJOR in $version_file"; return 1; }
    
    log_debug "Header verification passed"
}

# Main execution
main() {
    local noscrypt_dir="${1:-}"
    local openssl_version="${2:-$DEFAULT_OPENSSL_VERSION}"
    local openssl_vendor_dir="$noscrypt_dir/vendor/openssl"
    
    log_info "noscrypt OpenSSL header fix v$SCRIPT_VERSION"
    log_info "Target directory: $noscrypt_dir"
    log_info "OpenSSL version: $openssl_version"
    
    # Validate inputs
    validate_inputs "$noscrypt_dir"
    
    # Generate headers
    local config_file="$openssl_vendor_dir/configuration.h"
    local version_file="$openssl_vendor_dir/opensslv.h"
    
    log_info "Generating configuration.h..."
    generate_configuration_h "$config_file" "$openssl_version"
    
    log_info "Generating opensslv.h..."
    generate_opensslv_h "$version_file" "$openssl_version"
    
    # Verify headers
    verify_headers "$config_file" "$version_file"
    
    log_info "Success! OpenSSL headers generated:"
    log_info "  - $config_file"
    log_info "  - $version_file"
}

# Execute main function with all arguments
main "$@"