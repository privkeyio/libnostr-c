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

# Fix OpenSSL macro compatibility by defining missing macros
fix_openssl_macros() {
    local vendor_dir="$1"
    local openssl_version="$2"
    local major minor patch
    IFS='.' read -r major minor patch <<< "$openssl_version"
    
    # Only apply fixes for OpenSSL 1.1.x
    if [[ "$major.$minor" == "1.1" ]]; then
        log_info "Creating OpenSSL 1.1.x compatibility header..."
        
        # Create a global compatibility header that gets included first
        cat > "$vendor_dir/openssl_compat_fix.h" << 'EOF'
/*
 * OpenSSL 1.1.x compatibility fixes
 * This header defines macros that system OpenSSL 1.1.x headers expect but don't define
 */

#ifndef OPENSSL_COMPAT_FIX_H
#define OPENSSL_COMPAT_FIX_H

/* Map newer deprecation macros to older ones for OpenSSL 1.1.x compatibility */
#ifndef DEPRECATEDIN_1_1_0
# define DEPRECATEDIN_1_1_0(f) f
#endif

#ifndef DEPRECATEDIN_1_0_0  
# define DEPRECATEDIN_1_0_0(f) f
#endif

#ifndef DEPRECATEDIN_0_9_8
# define DEPRECATEDIN_0_9_8(f) f
#endif

/* ASN1 macros that system headers expect */
#ifndef DECLARE_ASN1_DUP_FUNCTION_name
# define DECLARE_ASN1_DUP_FUNCTION_name(type, name) \
    type *name##_dup(const type *a);
#endif

#ifndef DECLARE_ASN1_FUNCTIONS_name
# define DECLARE_ASN1_FUNCTIONS_name(type, name) \
    type *name##_new(void); \
    void name##_free(type *a); \
    DECLARE_ASN1_DUP_FUNCTION_name(type, name)
#endif

#ifndef DECLARE_ASN1_FUNCTIONS
# define DECLARE_ASN1_FUNCTIONS(type) DECLARE_ASN1_FUNCTIONS_name(type, type)
#endif

#endif /* OPENSSL_COMPAT_FIX_H */
EOF

        # Inject this compatibility header into key vendor headers that include system headers
        local headers_to_fix=("opensslconf.h" "macros.h")
        for header in "${headers_to_fix[@]}"; do
            local header_file="$vendor_dir/$header"
            if [[ -f "$header_file" ]] && ! grep -q "openssl_compat_fix.h" "$header_file"; then
                log_debug "Injecting compatibility header into $header"
                # Add include at the very top
                sed -i.bak '1i\
#include "openssl_compat_fix.h"
' "$header_file" 2>/dev/null || true
            fi
        done
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
# Create global OpenSSL compatibility wrapper for system headers
create_system_openssl_compat() {
    local noscrypt_dir="$1"
    local compat_header="$noscrypt_dir/src/openssl_system_compat.h"
    
    log_info "Creating system OpenSSL compatibility header..."
    
    cat > "$compat_header" << 'EOF'
/*
 * System OpenSSL Compatibility Header
 * Fixes missing DEPRECATEDIN_* macros in system OpenSSL installations
 * Generated by noscrypt header fix script
 */

#ifndef OPENSSL_SYSTEM_COMPAT_H
#define OPENSSL_SYSTEM_COMPAT_H

/* Define missing deprecation macros for OpenSSL 1.1.x compatibility */
#ifndef DEPRECATEDIN_1_1_0
# ifdef __GNUC__
#  define DEPRECATEDIN_1_1_0(f) f __attribute__((deprecated))
# elif defined(_MSC_VER)
#  define DEPRECATEDIN_1_1_0(f) __declspec(deprecated) f
# else
#  define DEPRECATEDIN_1_1_0(f) f
# endif
#endif

#ifndef DEPRECATEDIN_1_0_2
# ifdef __GNUC__
#  define DEPRECATEDIN_1_0_2(f) f __attribute__((deprecated))
# elif defined(_MSC_VER)
#  define DEPRECATEDIN_1_0_2(f) __declspec(deprecated) f
# else
#  define DEPRECATEDIN_1_0_2(f) f
# endif
#endif

#ifndef DEPRECATEDIN_3_0
# ifdef __GNUC__
#  define DEPRECATEDIN_3_0(f) f __attribute__((deprecated))
# elif defined(_MSC_VER)
#  define DEPRECATEDIN_3_0(f) __declspec(deprecated) f
# else
#  define DEPRECATEDIN_3_0(f) f
# endif
#endif

#endif /* OPENSSL_SYSTEM_COMPAT_H */
EOF

    # Inject the compatibility header into OpenSSL provider files
    local openssl_provider="$noscrypt_dir/src/providers/openssl.c"
    local openssl_helpers="$noscrypt_dir/src/providers/openssl-helpers.c"
    
    if [[ -f "$openssl_provider" ]]; then
        # Add compatibility include at the beginning of the file
        if ! grep -q "openssl_system_compat.h" "$openssl_provider"; then
            log_debug "Adding system compatibility to $openssl_provider"
            sed -i.bak '1i\
#include "../openssl_system_compat.h"
' "$openssl_provider"
        fi
    fi
    
    if [[ -f "$openssl_helpers" ]]; then
        # Add compatibility include at the beginning of the file  
        if ! grep -q "openssl_system_compat.h" "$openssl_helpers"; then
            log_debug "Adding system compatibility to $openssl_helpers"
            sed -i.bak '1i\
#include "../openssl_system_compat.h"
' "$openssl_helpers"
        fi
    fi
    
    log_debug "System OpenSSL compatibility header created at $compat_header"
}

# Add OpenSSL compatibility header and update CMakeLists.txt
add_cmake_openssl_compatibility() {
    local noscrypt_dir="$1"
    local cmake_file="$noscrypt_dir/CMakeLists.txt"
    local compat_header="$noscrypt_dir/include/openssl_compat.h"
    
    log_info "Creating production-grade OpenSSL compatibility solution..."
    
    if [[ ! -f "$cmake_file" ]]; then
        log_error "CMakeLists.txt not found at $cmake_file"
        return 1
    fi
    
    # Check if compatibility is already added
    if grep -q "openssl_compat.h" "$cmake_file"; then
        log_debug "OpenSSL compatibility already present in CMakeLists.txt"
        return 0
    fi
    
    # Create the compatibility header in the include directory
    log_debug "Creating OpenSSL compatibility header at $compat_header"
    cat > "$compat_header" << 'EOF'
/*
 * OpenSSL System Compatibility Header
 * Fixes missing DEPRECATEDIN_* macros in system OpenSSL installations
 * This is a production-grade solution that works across all platforms
 */

#ifndef OPENSSL_COMPAT_H
#define OPENSSL_COMPAT_H

/* Define missing deprecation macros for OpenSSL compatibility */
#ifndef DEPRECATEDIN_3_0
#  define DEPRECATEDIN_3_0(f) f
#endif

#ifndef DEPRECATEDIN_1_1_0  
#  define DEPRECATEDIN_1_1_0(f) f
#endif

#ifndef DEPRECATEDIN_1_0_2
#  define DEPRECATEDIN_1_0_2(f) f
#endif

#ifndef DEPRECATEDIN_1_0_1
#  define DEPRECATEDIN_1_0_1(f) f
#endif

#ifndef DEPRECATEDIN_1_0_0
#  define DEPRECATEDIN_1_0_0(f) f
#endif

#ifndef DEPRECATEDIN_0_9_8
#  define DEPRECATEDIN_0_9_8(f) f
#endif

#endif /* OPENSSL_COMPAT_H */
EOF
    
    # Use a simpler, more robust approach: always update CMakeLists.txt to force-include the header
    log_debug "Adding forced include to CMakeLists.txt"
    
    # Find a suitable insertion point - look for target_include_directories
    local include_line
    include_line=$(grep -n "target_include_directories.*PRIVATE include" "$cmake_file" | tail -1 | cut -d: -f1)
    
    if [[ -n "$include_line" ]]; then
        # Create backup
        cp "$cmake_file" "$cmake_file.bak"
        
        # Add force include after the last include directories line
        {
            head -n "$include_line" "$cmake_file"
            echo ""
            echo "# Force include OpenSSL compatibility header for all source files"
            echo "if(CRYPTO_LIB STREQUAL \"openssl\")"
            echo "    if(CMAKE_C_COMPILER_ID MATCHES \"Clang|GNU\")"
            echo "        target_compile_options(\${_NC_PROJ_NAME} PRIVATE -include \${CMAKE_SOURCE_DIR}/include/openssl_compat.h)"
            echo "        target_compile_options(\${_NC_PROJ_NAME}_static PRIVATE -include \${CMAKE_SOURCE_DIR}/include/openssl_compat.h)"
            echo "    elseif(MSVC)"
            echo "        target_compile_options(\${_NC_PROJ_NAME} PRIVATE /FI\${CMAKE_SOURCE_DIR}/include/openssl_compat.h)"
            echo "        target_compile_options(\${_NC_PROJ_NAME}_static PRIVATE /FI\${CMAKE_SOURCE_DIR}/include/openssl_compat.h)"
            echo "    endif()"
            echo "endif()"
            tail -n +$((include_line + 1)) "$cmake_file"
        } > "$cmake_file.tmp"
        
        if mv "$cmake_file.tmp" "$cmake_file"; then
            log_debug "CMakeLists.txt updated successfully"
            rm -f "$cmake_file.bak"
        else
            log_error "Failed to update CMakeLists.txt, restoring backup"
            mv "$cmake_file.bak" "$cmake_file" 2>/dev/null || true
            rm -f "$cmake_file.tmp"
            return 1
        fi
    else
        log_debug "Could not find suitable insertion point in CMakeLists.txt, trying alternative approach"
        
        # Fallback: append the configuration at the end of the file
        if {
            echo ""
            echo "# Force include OpenSSL compatibility header for all source files"
            echo "if(CRYPTO_LIB STREQUAL \"openssl\")"
            echo "    if(CMAKE_C_COMPILER_ID MATCHES \"Clang|GNU\")"
            echo "        target_compile_options(\${_NC_PROJ_NAME} PRIVATE -include \${CMAKE_SOURCE_DIR}/include/openssl_compat.h)"
            echo "        target_compile_options(\${_NC_PROJ_NAME}_static PRIVATE -include \${CMAKE_SOURCE_DIR}/include/openssl_compat.h)"
            echo "    elseif(MSVC)"
            echo "        target_compile_options(\${_NC_PROJ_NAME} PRIVATE /FI\${CMAKE_SOURCE_DIR}/include/openssl_compat.h)"
            echo "        target_compile_options(\${_NC_PROJ_NAME}_static PRIVATE /FI\${CMAKE_SOURCE_DIR}/include/openssl_compat.h)"
            echo "    endif()"
            echo "endif()"
        } >> "$cmake_file"; then
            log_debug "Appended compatibility configuration to CMakeLists.txt"
        else
            log_error "Failed to append compatibility configuration to CMakeLists.txt"
            return 1
        fi
    fi
    
    log_debug "OpenSSL compatibility solution implemented successfully"
    return 0
}

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
    
    # Fix OpenSSL 1.1.x macro compatibility issues
    fix_openssl_macros "$openssl_vendor_dir" "$openssl_version"
    
    # Create global OpenSSL compatibility for system headers
    create_system_openssl_compat "$noscrypt_dir"
    
    # Add compiler-level macro definitions for system OpenSSL compatibility
    if ! add_cmake_openssl_compatibility "$noscrypt_dir"; then
        log_error "Failed to add OpenSSL compatibility"
        exit 1
    fi
    
    # Verify headers
    if ! verify_headers "$config_file" "$version_file"; then
        log_error "Header verification failed"
        exit 1
    fi
    
    log_info "Success! OpenSSL headers generated:"
    log_info "  - $config_file"
    log_info "  - $version_file"
    
    return 0
}

# Execute main function with all arguments
main "$@"