cmake_minimum_required(VERSION 3.16)

if(ESP_PLATFORM)
    set(NOSTR_ESP_SOURCES
        "src/event.c"
        "src/key.c"
        "src/utils.c"
        "src/config.c"
        "src/features.c"
        "src/bech32.c"
        "src/nip44.c"
    )

    set(NOSTR_ESP_REQUIRES mbedtls noscrypt)
    set(NOSTR_ESP_PRIV_REQUIRES esp_system)

    if(CONFIG_NOSTR_JSON_SUPPORT)
        list(APPEND NOSTR_ESP_REQUIRES json)
    endif()

    idf_build_get_property(build_dir BUILD_DIR)
    file(MAKE_DIRECTORY "${build_dir}/noscrypt")
    file(GLOB NC_HEADERS "${CMAKE_CURRENT_LIST_DIR}/../noscrypt/include/*.h")
    foreach(header ${NC_HEADERS})
        get_filename_component(header_name ${header} NAME)
        if(NOT EXISTS "${build_dir}/noscrypt/${header_name}")
            file(CREATE_LINK "${header}" "${build_dir}/noscrypt/${header_name}" SYMBOLIC)
        endif()
    endforeach()

    set(NOSTR_FEATURE_ENCODING 1)
    set(NOSTR_FEATURE_CRYPTO_NOSCRYPT 1)
    set(HAVE_NOSCRYPT 1)
    set(HAVE_MBEDTLS 1)
    configure_file(
        "${CMAKE_CURRENT_LIST_DIR}/include/nostr_features.h.in"
        "${build_dir}/nostr_features.h"
        @ONLY
    )

    idf_component_register(
        SRCS ${NOSTR_ESP_SOURCES}
        INCLUDE_DIRS "include" "${build_dir}"
        REQUIRES ${NOSTR_ESP_REQUIRES}
        PRIV_REQUIRES ${NOSTR_ESP_PRIV_REQUIRES}
    )

    target_compile_definitions(${COMPONENT_LIB} PUBLIC
        NOSTR_FEATURE_STD=1
        NOSTR_FEATURE_EVENTS=1
        NOSTR_FEATURE_KEYS=1
        NOSTR_FEATURE_THREADING=0
    )

    return()
endif()

project(libnostr-c VERSION 0.1.2 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Windows and MSVC-specific configuration
if(WIN32)
    # Target Windows 7+ (NT 6.1+) for modern API support
    add_compile_definitions(_WIN32_WINNT=0x0601 WINVER=0x0601)
    
    if(MSVC)
        # Use /std:c11 for C99+ features support
        add_compile_options(/std:c11)
        # Disable warnings about deprecated functions
        add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    elseif(MINGW)
        # MinGW-specific flags
        add_compile_options(-std=c99)
    endif()
endif()

# =============================================================================
# Feature Flags - Modular Library Compilation
# =============================================================================

# Core features (always enabled)
set(NOSTR_FEATURE_STD ON CACHE BOOL "Enable standard library (always on)")
set(NOSTR_FEATURE_EVENTS ON CACHE BOOL "Enable event management (always on)")
set(NOSTR_FEATURE_KEYS ON CACHE BOOL "Enable key management (always on)")
set(NOSTR_FEATURE_ENCODING ON CACHE BOOL "Enable bech32/hex encoding (always on)")

# NIP features (optional)
option(NOSTR_FEATURE_ALL_NIPS "Enable all NIPs" OFF)
option(NOSTR_FEATURE_NIP04 "Enable NIP-04: Legacy Encrypted Direct Messages (deprecated)" OFF)
option(NOSTR_FEATURE_NIP13 "Enable NIP-13: Proof of Work" ON)
option(NOSTR_FEATURE_NIP17 "Enable NIP-17: Private Direct Messages" OFF)
option(NOSTR_FEATURE_NIP44 "Enable NIP-44: Encrypted Payloads v2" OFF)
option(NOSTR_FEATURE_NIP47 "Enable NIP-47: Nostr Wallet Connect" OFF)
option(NOSTR_FEATURE_NIP57 "Enable NIP-57: Lightning Zaps" ON)
option(NOSTR_FEATURE_NIP59 "Enable NIP-59: Gift Wrap" OFF)
option(NOSTR_FEATURE_RELAY_PROTOCOL "Enable NIP-01 relay-side protocol support" ON)

# Check if JSON_ENHANCED was set by user/preset before defining the option
# This includes command line, presets, or parent CMake files
if(DEFINED NOSTR_FEATURE_JSON_ENHANCED)
    set(NOSTR_FEATURE_JSON_ENHANCED_SET_BY_USER ON)
    set(NOSTR_FEATURE_JSON_ENHANCED_USER_VALUE ${NOSTR_FEATURE_JSON_ENHANCED})
else()
    set(NOSTR_FEATURE_JSON_ENHANCED_SET_BY_USER OFF)
    set(NOSTR_FEATURE_JSON_ENHANCED_USER_VALUE OFF)
endif()

# Optional enhancements
option(NOSTR_FEATURE_RELAY "Enable relay communication (requires libwebsockets)" ON)
option(NOSTR_FEATURE_HD_KEYS "Enable HD key derivation (requires noscrypt)" OFF)
option(NOSTR_FEATURE_JSON_ENHANCED "Enable enhanced JSON handling (requires cJSON)" OFF)
option(NOSTR_FEATURE_THREADING "Enable multi-threaded operations" ON)

# Library path hints (following noscrypt pattern)
set(CRYPTO_LIB_DIR "" CACHE STRING "Path to crypto library directory if not globally available")
set(CJSON_LIB_DIR "" CACHE STRING "Path to cJSON library directory if not globally available")
set(SECP256K1_LIB_DIR "" CACHE STRING "Path to secp256k1 library directory if not globally available")

# Cryptography backend options (one must be enabled)
option(NOSTR_FEATURE_CRYPTO_NOSCRYPT "Use noscrypt for cryptography (preferred)" ON)
option(NOSTR_FEATURE_CRYPTO_SECP256K1 "Use secp256k1 for basic cryptography (fallback)" ON)

# Handle all-nips flag
if(NOSTR_FEATURE_ALL_NIPS)
    set(NOSTR_FEATURE_NIP04 ON)
    set(NOSTR_FEATURE_NIP13 ON)
    set(NOSTR_FEATURE_NIP17 ON)
    set(NOSTR_FEATURE_NIP44 ON)
    set(NOSTR_FEATURE_NIP47 ON)
    set(NOSTR_FEATURE_NIP57 ON)
    set(NOSTR_FEATURE_NIP59 ON)
    set(NOSTR_FEATURE_HD_KEYS ON)
endif()

# Set RPATH to prefer /usr/local/lib
set(CMAKE_INSTALL_RPATH "/usr/local/lib")
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# =============================================================================
# Dependency Detection and Feature Validation
# =============================================================================

find_package(PkgConfig QUIET)
find_package(OpenSSL REQUIRED)

# Always required
find_package(Threads REQUIRED)

# Detect available libraries
# First try vcpkg packages if using vcpkg
if(DEFINED CMAKE_TOOLCHAIN_FILE AND CMAKE_TOOLCHAIN_FILE MATCHES "vcpkg")
    find_package(cjson CONFIG QUIET)
    find_package(unofficial-libwebsockets CONFIG QUIET)
    find_package(unofficial-secp256k1 CONFIG QUIET)
    
    # Map vcpkg findings to our variables
    if(cjson_FOUND)
        set(CJSON_FOUND TRUE)
        set(CJSON_LIBRARIES cjson)
    endif()
    if(unofficial-libwebsockets_FOUND)
        set(LIBWEBSOCKETS_FOUND TRUE)
        set(LIBWEBSOCKETS_LIBRARIES unofficial::libwebsockets::libwebsockets)
    endif()
    if(unofficial-secp256k1_FOUND)
        set(SECP256K1_FOUND TRUE)
        set(SECP256K1_LIBRARIES unofficial::secp256k1::secp256k1)
    endif()
endif()

# Fallback to pkg-config if vcpkg didn't find packages
if(PkgConfig_FOUND AND NOT (CJSON_FOUND AND LIBWEBSOCKETS_FOUND))
    if(NOT CJSON_FOUND)
        pkg_check_modules(CJSON libcjson)
    endif()
    if(NOT SECP256K1_FOUND)
        pkg_check_modules(SECP256K1 libsecp256k1)
    endif()
    if(NOT LIBWEBSOCKETS_FOUND)
        pkg_check_modules(LIBWEBSOCKETS libwebsockets)
    endif()
    pkg_check_modules(NOSCRYPT noscrypt)
    
    # Check for noscrypt in common development locations
    if(NOT NOSCRYPT_FOUND)
        # Check environment variable first
        if(DEFINED ENV{NOSCRYPT_DIR})
            set(NOSCRYPT_SEARCH_PATHS 
                $ENV{NOSCRYPT_DIR}/lib 
                $ENV{NOSCRYPT_DIR}/build
                $ENV{NOSCRYPT_DIR}
            )
        else()
            # Check common relative locations for development
            set(NOSCRYPT_SEARCH_PATHS 
                ${CMAKE_CURRENT_SOURCE_DIR}/../noscrypt/lib
                ${CMAKE_CURRENT_SOURCE_DIR}/../noscrypt/build
                ${CMAKE_CURRENT_SOURCE_DIR}/../noscrypt
                ${CMAKE_CURRENT_SOURCE_DIR}/external/noscrypt/lib
                ${CMAKE_CURRENT_SOURCE_DIR}/external/noscrypt/build
                ${CMAKE_CURRENT_SOURCE_DIR}/vendor/noscrypt/lib
                ${CMAKE_CURRENT_SOURCE_DIR}/vendor/noscrypt/build
            )
        endif()
        
        find_library(NOSCRYPT_LOCAL_LIB 
            NAMES noscrypt libnoscrypt
            PATHS ${NOSCRYPT_SEARCH_PATHS}
            NO_DEFAULT_PATH
        )
        
        if(NOSCRYPT_LOCAL_LIB)
            # Determine include search paths based on found library location
            get_filename_component(NOSCRYPT_LIB_DIR ${NOSCRYPT_LOCAL_LIB} DIRECTORY)
            get_filename_component(NOSCRYPT_ROOT_DIR ${NOSCRYPT_LIB_DIR} DIRECTORY)
            
            find_path(NOSCRYPT_LOCAL_INCLUDE
                NAMES noscrypt.h
                PATHS 
                    ${NOSCRYPT_ROOT_DIR}/include
                    ${NOSCRYPT_ROOT_DIR}
                    ${NOSCRYPT_LIB_DIR}/../include
                NO_DEFAULT_PATH
            )
            
            if(NOSCRYPT_LOCAL_INCLUDE)
                set(NOSCRYPT_FOUND TRUE)
                set(NOSCRYPT_LIBRARIES ${NOSCRYPT_LOCAL_LIB})
                set(NOSCRYPT_INCLUDE_DIRS ${NOSCRYPT_LOCAL_INCLUDE})
                message(STATUS "Found local noscrypt: ${NOSCRYPT_LOCAL_LIB}")
                message(STATUS "Using noscrypt headers: ${NOSCRYPT_LOCAL_INCLUDE}")
            endif()
        endif()
    endif()
endif()

# Fallback detection for libraries not found via pkg-config
if(NOT CJSON_FOUND)
    # Try standard system library search first
    if(WIN32)
        # Windows 7+ library detection - prefer vcpkg and modern package managers
        find_library(CJSON_LIBRARIES NAMES cjson libcjson cjson.lib cjson_d.lib libcjson_d)
    else()
        find_library(CJSON_LIBRARIES NAMES cjson libcjson)
    endif()
    
    # If not found, try common paths
    if(NOT CJSON_LIBRARIES)
        if(WIN32)
            # Modern Windows (7+) library detection - following noscrypt patterns
            find_library(CJSON_LIBRARIES 
                NAMES cjson libcjson cjson.lib cjson_d.lib libcjson_d libcjson.a cjson.a
                
                HINTS 
                    ${CJSON_LIB_DIR} 
                    ${CJSON_LIB_DIR}/debug 
                    ${CJSON_LIB_DIR}/release 
                    ${CJSON_LIB_DIR}/lib
                    ${CJSON_LIB_DIR}/lib/debug 
                    ${CJSON_LIB_DIR}/lib/release
                
                PATHS 
                    # vcpkg (preferred)
                    "C:/vcpkg/installed/x64-windows/lib" 
                    "C:/vcpkg/installed/x64-windows/debug/lib"
                    "${VCPKG_INSTALLED_DIR}/x64-windows/lib"
                    "${VCPKG_INSTALLED_DIR}/x64-windows/debug/lib"
                    # Conan
                    "${CMAKE_PREFIX_PATH}/lib"
                    "${CMAKE_PREFIX_PATH}/lib64"
                    # Manual install
                    "C:/Program Files/cJSON/lib"
                    "C:/Program Files (x86)/cJSON/lib"
                NO_DEFAULT_PATH
            )
        else()
            find_library(CJSON_LIBRARIES 
                NAMES cjson libcjson
                PATHS /usr/local/lib /opt/homebrew/lib /usr/lib
                NO_DEFAULT_PATH
            )
        endif()
    endif()
    
    # Find include directory if library was found
    if(CJSON_LIBRARIES)
        find_path(CJSON_INCLUDE_DIRS cjson/cJSON.h)
        if(NOT CJSON_INCLUDE_DIRS)
            if(WIN32)
                find_path(CJSON_INCLUDE_DIRS cjson/cJSON.h 
                    PATHS 
                        # vcpkg (preferred)
                        "C:/vcpkg/installed/x64-windows/include"
                        "${VCPKG_INSTALLED_DIR}/x64-windows/include"
                        # Conan
                        "${CMAKE_PREFIX_PATH}/include"
                        # Manual install
                        "C:/Program Files/cJSON/include"
                    NO_DEFAULT_PATH
                )
            else()
                find_path(CJSON_INCLUDE_DIRS cjson/cJSON.h 
                    PATHS /usr/local/include /opt/homebrew/include /usr/include
                    NO_DEFAULT_PATH
                )
            endif()
        endif()
        if(CJSON_INCLUDE_DIRS)
            set(CJSON_FOUND TRUE)
            message(STATUS "Found cJSON library: ${CJSON_LIBRARIES}")
            message(STATUS "Found cJSON headers: ${CJSON_INCLUDE_DIRS}")
        endif()
    endif()
    
    # Final fallback - try to link by name only (for system-installed packages)
    if(NOT CJSON_FOUND)
        # Check if we can at least find the header file
        find_path(CJSON_INCLUDE_DIRS cjson/cJSON.h)
        if(CJSON_INCLUDE_DIRS)
            # Try to verify we can actually link against the library
            include(CheckLibraryExists)
            check_library_exists(cjson cJSON_CreateObject "" CJSON_LINKABLE)
            if(CJSON_LINKABLE)
                set(CJSON_FOUND TRUE)
                set(CJSON_LIBRARIES "cjson")  # Use library name for linking
                message(STATUS "Using system cJSON (verified linkable)")
            else()
                message(STATUS "Found cJSON headers but library not linkable - disabling JSON_ENHANCED")
            endif()
        endif()
    endif()
endif()

# Auto-enable JSON_ENHANCED if cJSON is available and not explicitly disabled
# Following noscrypt pattern for compiler-specific defaults
if(CJSON_FOUND AND NOT NOSTR_FEATURE_JSON_ENHANCED_SET_BY_USER)
    if(MSVC)
        # Keep JSON_ENHANCED OFF by default on MSVC to avoid dependency issues
        message(STATUS "cJSON found on MSVC but keeping JSON_ENHANCED OFF by default")
        message(STATUS "Enable explicitly with -DNOSTR_FEATURE_JSON_ENHANCED=ON if desired")
    else()
        set(NOSTR_FEATURE_JSON_ENHANCED ON CACHE BOOL "Enable enhanced JSON handling (requires cJSON)" FORCE)
        message(STATUS "Auto-enabling JSON_ENHANCED feature since cJSON is available")
    endif()
elseif(NOSTR_FEATURE_JSON_ENHANCED_SET_BY_USER AND NOT NOSTR_FEATURE_JSON_ENHANCED_USER_VALUE)
    message(STATUS "JSON_ENHANCED explicitly disabled by user/preset")
endif()

if(NOT SECP256K1_FOUND)
    # Following noscrypt's secp256k1 detection pattern
    if(SECP256K1_LIB_DIR)
        # Search for library in user-specified directory first
        find_library(SECP256K1_LIBRARIES
            NAMES secp256k1 libsecp256k1 secp256k1.lib libsecp256k1.a secp256k1.a
            PATHS ${SECP256K1_LIB_DIR}
            REQUIRED
        )
    elseif(WIN32)
        # Windows-specific secp256k1 detection - following noscrypt patterns
        find_library(SECP256K1_LIBRARIES 
            NAMES secp256k1 libsecp256k1 secp256k1.lib libsecp256k1.a secp256k1.a
            
            HINTS 
                ${CRYPTO_LIB_DIR} 
                ${CRYPTO_LIB_DIR}/debug 
                ${CRYPTO_LIB_DIR}/release 
                ${CRYPTO_LIB_DIR}/lib
                ${CRYPTO_LIB_DIR}/lib/debug 
                ${CRYPTO_LIB_DIR}/lib/release
            
            PATHS 
                # GitHub Actions CI install path
                "C:/Program Files/secp256k1/lib"
                "C:/Program Files (x86)/secp256k1/lib"
                # vcpkg paths
                "C:/vcpkg/installed/x64-windows/lib" 
                "C:/vcpkg/installed/x64-windows/debug/lib"
                "${VCPKG_INSTALLED_DIR}/x64-windows/lib"
                "${VCPKG_INSTALLED_DIR}/x64-windows/debug/lib"
                # Conan
                "${CMAKE_PREFIX_PATH}/lib"
                "${CMAKE_PREFIX_PATH}/lib64"
            NO_DEFAULT_PATH
        )
        if(NOT SECP256K1_LIBRARIES)
            # Fallback to global search on Windows
            find_library(SECP256K1_LIBRARIES NAMES secp256k1 libsecp256k1 secp256k1.lib)
        endif()
        
        # Find include directories for Windows
        if(SECP256K1_LIBRARIES)
            find_path(SECP256K1_INCLUDE_DIRS secp256k1.h
                HINTS
                    ${SECP256K1_LIB_DIR}/../include
                    ${CRYPTO_LIB_DIR}/../include
                PATHS 
                    # GitHub Actions CI install path
                    "C:/Program Files/secp256k1/include"
                    "C:/Program Files (x86)/secp256k1/include"
                    # vcpkg paths
                    "C:/vcpkg/installed/x64-windows/include"
                    "${VCPKG_INSTALLED_DIR}/x64-windows/include"
                    # Conan
                    "${CMAKE_PREFIX_PATH}/include"
                NO_DEFAULT_PATH
            )
            if(SECP256K1_INCLUDE_DIRS)
                set(SECP256K1_FOUND TRUE)
                message(STATUS "Found secp256k1 library: ${SECP256K1_LIBRARIES}")
                message(STATUS "Found secp256k1 headers: ${SECP256K1_INCLUDE_DIRS}")
            endif()
        endif()
    else()
        # Try global search for other platforms
        find_library(SECP256K1_LIBRARIES NAMES secp256k1 libsecp256k1)
    endif()
    
    # Handle include directory detection for all platforms when using SECP256K1_LIB_DIR
    if(SECP256K1_LIB_DIR AND SECP256K1_LIBRARIES AND NOT SECP256K1_INCLUDE_DIRS)
        find_path(SECP256K1_INCLUDE_DIRS secp256k1.h
            PATHS ${SECP256K1_LIB_DIR}/../include
            NO_DEFAULT_PATH
        )
        if(SECP256K1_INCLUDE_DIRS)
            set(SECP256K1_FOUND TRUE)
            message(STATUS "Found secp256k1 library (custom path): ${SECP256K1_LIBRARIES}")
            message(STATUS "Found secp256k1 headers (custom path): ${SECP256K1_INCLUDE_DIRS}")
        endif()
    endif()
    
    # Unix-like system fallback  
    if(NOT WIN32 AND NOT SECP256K1_LIBRARIES)
        find_library(SECP256K1_LIBRARIES 
            NAMES secp256k1
            PATHS /usr/local/lib
            NO_DEFAULT_PATH
        )
        if(NOT SECP256K1_LIBRARIES)
            find_library(SECP256K1_LIBRARIES secp256k1)
        endif()
    endif()
endif()

if(NOT LIBWEBSOCKETS_FOUND)
    if(WIN32)
        # Windows-specific libwebsockets detection
        find_library(LIBWEBSOCKETS_LIBRARIES 
            NAMES websockets libwebsockets websockets.lib libwebsockets.a websockets.a
            
            PATHS 
                # vcpkg paths
                "C:/vcpkg/installed/x64-windows/lib" 
                "C:/vcpkg/installed/x64-windows/debug/lib"
                "${VCPKG_INSTALLED_DIR}/x64-windows/lib"
                "${VCPKG_INSTALLED_DIR}/x64-windows/debug/lib"
                # Conan
                "${CMAKE_PREFIX_PATH}/lib"
                "${CMAKE_PREFIX_PATH}/lib64"
            NO_DEFAULT_PATH
        )
        if(NOT LIBWEBSOCKETS_LIBRARIES)
            # Fallback to global search on Windows
            find_library(LIBWEBSOCKETS_LIBRARIES NAMES websockets libwebsockets websockets.lib)
        endif()
    else()
        # Unix-like systems
        find_library(LIBWEBSOCKETS_LIBRARIES websockets)
    endif()
endif()

if(NOT NOSCRYPT_FOUND)
    find_library(NOSCRYPT_LIBRARIES noscrypt PATHS /usr/local/lib NO_DEFAULT_PATH)
endif()

# =============================================================================
# Feature Validation and Dependency Enforcement
# =============================================================================

# Validate cryptography backend
set(HAVE_CRYPTO_BACKEND OFF)

if(NOSTR_FEATURE_CRYPTO_NOSCRYPT AND (NOSCRYPT_FOUND OR (NOSCRYPT_LIBRARIES AND NOT NOSCRYPT_LIBRARIES STREQUAL "NOTFOUND")))
    set(HAVE_NOSCRYPT ON)
    set(HAVE_CRYPTO_BACKEND ON)
    message(STATUS "Using noscrypt for cryptography")
    if(NOSCRYPT_LIBRARIES AND NOT NOSCRYPT_LIBRARIES STREQUAL "NOTFOUND")
        include_directories(/usr/local/include)
        link_directories(/usr/local/lib)
    endif()
endif()

if(NOSTR_FEATURE_CRYPTO_SECP256K1 AND (SECP256K1_FOUND OR (SECP256K1_LIBRARIES AND NOT SECP256K1_LIBRARIES STREQUAL "NOTFOUND")))
    set(HAVE_SECP256K1 ON)
    set(HAVE_CRYPTO_BACKEND ON)
    message(STATUS "Using secp256k1 for cryptography")
    
    # Check for required schnorr functions
    if(SECP256K1_LIBRARIES AND NOT SECP256K1_LIBRARIES STREQUAL "NOTFOUND")
        include(CheckLibraryExists)
        check_library_exists(${SECP256K1_LIBRARIES} secp256k1_schnorrsig_sign32 "" HAVE_SCHNORRSIG_SIGN32)
        if(NOT HAVE_SCHNORRSIG_SIGN32)
            message(WARNING "secp256k1 lacks schnorrsig support - some features may be limited")
        endif()
    endif()
endif()

# Ensure at least one crypto backend is available
if(NOT HAVE_CRYPTO_BACKEND)
    if(WIN32)
        # On Windows, gracefully disable crypto features if no backend available
        message(WARNING "No cryptography backend available on Windows - disabling crypto-dependent features")
        message(STATUS "Consider installing secp256k1 via: vcpkg install secp256k1")
        set(NOSTR_FEATURE_NIP04 OFF)
        set(NOSTR_FEATURE_NIP17 OFF) 
        set(NOSTR_FEATURE_NIP44 OFF)
        set(NOSTR_FEATURE_NIP47 OFF)
        set(NOSTR_FEATURE_NIP59 OFF)
        set(NOSTR_FEATURE_HD_KEYS OFF)
    else()
        message(FATAL_ERROR "No cryptography backend available. Install noscrypt or secp256k1.")
    endif()
endif()

# Validate feature dependencies
set(FEATURES_REQUIRING_NOSCRYPT "NIP04;NIP17;NIP44;NIP47;NIP59;HD_KEYS")
foreach(FEATURE ${FEATURES_REQUIRING_NOSCRYPT})
    if(NOSTR_FEATURE_${FEATURE} AND NOT HAVE_NOSCRYPT)
        message(FATAL_ERROR "Feature ${FEATURE} requires noscrypt but it's not available")
    endif()
endforeach()

# Auto-disable RELAY on Windows if libwebsockets not found (following noscrypt pattern)
if(WIN32 AND NOSTR_FEATURE_RELAY AND NOT (LIBWEBSOCKETS_FOUND OR LIBWEBSOCKETS_LIBRARIES))
    message(STATUS "RELAY feature requested but libwebsockets not found on Windows - disabling feature")
    message(STATUS "Consider installing libwebsockets via: vcpkg install libwebsockets")
    set(NOSTR_FEATURE_RELAY OFF)
endif()

if(NOSTR_FEATURE_RELAY AND NOT (LIBWEBSOCKETS_FOUND OR LIBWEBSOCKETS_LIBRARIES))
    message(FATAL_ERROR "RELAY feature requires libwebsockets but it's not available")
endif()

# RELAY feature requires JSON parsing - force enable JSON_ENHANCED if RELAY is enabled
if(NOSTR_FEATURE_RELAY AND NOT NOSTR_FEATURE_JSON_ENHANCED AND (CJSON_FOUND OR CJSON_LIBRARIES))
    message(STATUS "RELAY feature requires JSON parsing - auto-enabling JSON_ENHANCED")
    set(NOSTR_FEATURE_JSON_ENHANCED ON CACHE BOOL "Enable enhanced JSON handling (requires cJSON)" FORCE)
elseif(NOSTR_FEATURE_RELAY AND NOT NOSTR_FEATURE_JSON_ENHANCED)
    message(FATAL_ERROR "RELAY feature requires JSON parsing but cJSON is not available. Install cJSON or disable RELAY feature.")
endif()

# Following noscrypt pattern for dependency handling
if(NOSTR_FEATURE_JSON_ENHANCED AND NOT CJSON_FOUND AND NOT CJSON_LIBRARIES)
    if(MSVC)
        message(STATUS "JSON_ENHANCED requested but cJSON not found on MSVC - disabling feature")
        message(STATUS "Consider installing cJSON via: vcpkg install cjson")
        set(NOSTR_FEATURE_JSON_ENHANCED OFF)
    else()
        message(WARNING "JSON_ENHANCED requested but cJSON not found - falling back to basic JSON")
        set(NOSTR_FEATURE_JSON_ENHANCED OFF)
    endif()
endif()

# Set final library availability flags
set(HAVE_CJSON OFF)
if((CJSON_FOUND OR CJSON_LIBRARIES) AND NOSTR_FEATURE_JSON_ENHANCED)
    set(HAVE_CJSON ON)
    message(STATUS "cJSON support enabled: CJSON_FOUND=${CJSON_FOUND}, CJSON_LIBRARIES=${CJSON_LIBRARIES}")
else()
    message(STATUS "cJSON support disabled: CJSON_FOUND=${CJSON_FOUND}, CJSON_LIBRARIES=${CJSON_LIBRARIES}, NOSTR_FEATURE_JSON_ENHANCED=${NOSTR_FEATURE_JSON_ENHANCED}")
endif()

set(HAVE_LIBWEBSOCKETS OFF)
if((LIBWEBSOCKETS_FOUND OR LIBWEBSOCKETS_LIBRARIES) AND NOSTR_FEATURE_RELAY)
    set(HAVE_LIBWEBSOCKETS ON)
endif()

# =============================================================================
# Generate Feature Detection Header
# =============================================================================

# Feature header generation moved to after linking validation

# =============================================================================
# Conditional Source Compilation
# =============================================================================

# Core sources (always included)
set(NOSTR_CORE_SOURCES
    src/event.c
    src/key.c
    src/utils.c
    src/config.c
    src/features.c
)

# Conditional sources based on features
set(NOSTR_SOURCES ${NOSTR_CORE_SOURCES})

if(NOSTR_FEATURE_ENCODING)
    list(APPEND NOSTR_SOURCES src/bech32.c)
endif()

if(NOSTR_FEATURE_RELAY)
    list(APPEND NOSTR_SOURCES src/relay.c)
endif()

if(NOSTR_FEATURE_NIP13)
    list(APPEND NOSTR_SOURCES src/nip13.c)
endif()

if(NOSTR_FEATURE_NIP17)
    list(APPEND NOSTR_SOURCES src/nip17.c)
endif()

if(NOSTR_FEATURE_NIP44 OR NOSTR_FEATURE_NIP04)
    list(APPEND NOSTR_SOURCES src/nip44.c)
endif()

if(NOSTR_FEATURE_NIP47)
    list(APPEND NOSTR_SOURCES 
        src/nip47.c
        src/nip47_session.c
        src/nip47_commands.c
    )
endif()

if(NOSTR_FEATURE_NIP57)
    list(APPEND NOSTR_SOURCES src/zap.c)
endif()

if(NOSTR_FEATURE_NIP59)
    list(APPEND NOSTR_SOURCES src/nip59.c)
endif()

if(NOSTR_FEATURE_HD_KEYS)
    list(APPEND NOSTR_SOURCES src/hd_key.c)
endif()

if(NOSTR_FEATURE_RELAY_PROTOCOL)
    list(APPEND NOSTR_SOURCES src/relay_protocol.c)
endif()

add_library(nostr SHARED ${NOSTR_SOURCES})
add_library(nostr_static STATIC ${NOSTR_SOURCES})

target_include_directories(nostr PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_include_directories(nostr_static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>  
    $<INSTALL_INTERFACE:include>
)

# Add include directories for dependencies
if(CJSON_FOUND)
    target_include_directories(nostr PRIVATE ${CJSON_INCLUDE_DIRS})
    target_include_directories(nostr_static PRIVATE ${CJSON_INCLUDE_DIRS})
endif()

if(SECP256K1_FOUND)
    target_include_directories(nostr PRIVATE ${SECP256K1_INCLUDE_DIRS})
    target_include_directories(nostr_static PRIVATE ${SECP256K1_INCLUDE_DIRS})
endif()

if(LIBWEBSOCKETS_FOUND)
    target_include_directories(nostr PRIVATE ${LIBWEBSOCKETS_INCLUDE_DIRS})
    target_include_directories(nostr_static PRIVATE ${LIBWEBSOCKETS_INCLUDE_DIRS})
endif()

if(NOSCRYPT_FOUND)
    target_include_directories(nostr PRIVATE ${NOSCRYPT_INCLUDE_DIRS})
    target_include_directories(nostr_static PRIVATE ${NOSCRYPT_INCLUDE_DIRS})
endif()

# Link required libraries
set(NOSTR_LINK_LIBRARIES OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

# Add optional libraries if they exist
if(HAVE_CJSON)
    if(CJSON_FOUND)
        # Use pkg-config link libraries directly
        if(CJSON_LINK_LIBRARIES)
            list(APPEND NOSTR_LINK_LIBRARIES ${CJSON_LINK_LIBRARIES})
            message(STATUS "Linking with cJSON libraries from pkg-config: ${CJSON_LINK_LIBRARIES}")
        else()
            # Fallback to manual library detection
            find_library(CJSON_MANUAL_LIB 
                NAMES cjson libcjson
                PATHS /opt/homebrew/lib /usr/local/lib
                NO_DEFAULT_PATH
            )
            if(CJSON_MANUAL_LIB)
                list(APPEND NOSTR_LINK_LIBRARIES ${CJSON_MANUAL_LIB})
                message(STATUS "Linking with manually found cJSON library: ${CJSON_MANUAL_LIB}")
            else()
                list(APPEND NOSTR_LINK_LIBRARIES cjson) 
                message(STATUS "Linking with cJSON library by name: cjson (fallback)")
            endif()
        endif()
    elseif(CJSON_LIBRARIES AND NOT CJSON_LIBRARIES STREQUAL "NOTFOUND")
        list(APPEND NOSTR_LINK_LIBRARIES ${CJSON_LIBRARIES})
        message(STATUS "Linking with detected cJSON library: ${CJSON_LIBRARIES}")
    else()
        # macOS-specific fallback: try common Homebrew paths
        if(APPLE)
            find_library(CJSON_HOMEBREW_LIB 
                NAMES cjson libcjson
                PATHS /opt/homebrew/lib /usr/local/lib
                NO_DEFAULT_PATH
            )
            if(CJSON_HOMEBREW_LIB)
                list(APPEND NOSTR_LINK_LIBRARIES ${CJSON_HOMEBREW_LIB})
                message(STATUS "Linking with Homebrew cJSON library: ${CJSON_HOMEBREW_LIB}")
            else()
                # Last resort - try linking by name
                list(APPEND NOSTR_LINK_LIBRARIES cjson)
                message(STATUS "Linking with cJSON library by name (macOS fallback): cjson")
            endif()
        else()
            # Last resort - try linking by name
            list(APPEND NOSTR_LINK_LIBRARIES cjson)
            message(STATUS "Linking with cJSON library by name (fallback): cjson")
        endif()
    endif()
else()
    message(STATUS "cJSON linking disabled - HAVE_CJSON is OFF")
endif()

if(HAVE_LIBWEBSOCKETS)
    if(LIBWEBSOCKETS_FOUND)
        # Use pkg-config link libraries directly
        if(LIBWEBSOCKETS_LINK_LIBRARIES)
            list(APPEND NOSTR_LINK_LIBRARIES ${LIBWEBSOCKETS_LINK_LIBRARIES})
            message(STATUS "Linking with libwebsockets libraries from pkg-config: ${LIBWEBSOCKETS_LINK_LIBRARIES}")
        else()
            # Fallback to manual library detection
            find_library(LIBWEBSOCKETS_MANUAL_LIB 
                NAMES websockets libwebsockets
                PATHS /opt/homebrew/lib /usr/local/lib
                NO_DEFAULT_PATH
            )
            if(LIBWEBSOCKETS_MANUAL_LIB)
                list(APPEND NOSTR_LINK_LIBRARIES ${LIBWEBSOCKETS_MANUAL_LIB})
                message(STATUS "Linking with manually found libwebsockets library: ${LIBWEBSOCKETS_MANUAL_LIB}")
            else()
                list(APPEND NOSTR_LINK_LIBRARIES websockets) 
                message(STATUS "Linking with libwebsockets library by name: websockets (fallback)")
            endif()
        endif()
    elseif(LIBWEBSOCKETS_LIBRARIES AND NOT LIBWEBSOCKETS_LIBRARIES STREQUAL "NOTFOUND")
        list(APPEND NOSTR_LINK_LIBRARIES ${LIBWEBSOCKETS_LIBRARIES})
        message(STATUS "Linking with detected libwebsockets library: ${LIBWEBSOCKETS_LIBRARIES}")
    endif()
endif()

if(NOSCRYPT_LIBRARIES AND NOT NOSCRYPT_LIBRARIES STREQUAL "NOTFOUND")
    list(APPEND NOSTR_LINK_LIBRARIES ${NOSCRYPT_LIBRARIES})
endif()

if(HAVE_SECP256K1)
    if(SECP256K1_FOUND)
        # Use pkg-config link libraries directly
        if(SECP256K1_LINK_LIBRARIES)
            list(APPEND NOSTR_LINK_LIBRARIES ${SECP256K1_LINK_LIBRARIES})
            message(STATUS "Linking with secp256k1 libraries from pkg-config: ${SECP256K1_LINK_LIBRARIES}")
        else()
            # Fallback to manual library detection
            find_library(SECP256K1_MANUAL_LIB 
                NAMES secp256k1 libsecp256k1
                PATHS /opt/homebrew/lib /usr/local/lib
                NO_DEFAULT_PATH
            )
            if(SECP256K1_MANUAL_LIB)
                list(APPEND NOSTR_LINK_LIBRARIES ${SECP256K1_MANUAL_LIB})
                message(STATUS "Linking with manually found secp256k1 library: ${SECP256K1_MANUAL_LIB}")
            else()
                # Don't try to link by name on Windows as it will fail
                if(NOT WIN32)
                    list(APPEND NOSTR_LINK_LIBRARIES secp256k1) 
                    message(STATUS "Linking with secp256k1 library by name: secp256k1 (fallback)")
                else()
                    message(WARNING "secp256k1 not found on Windows - disabling secp256k1 backend")
                    set(HAVE_SECP256K1 OFF)
                endif()
            endif()
        endif()
    elseif(SECP256K1_LIBRARIES AND NOT SECP256K1_LIBRARIES STREQUAL "NOTFOUND")
        list(APPEND NOSTR_LINK_LIBRARIES ${SECP256K1_LIBRARIES})
        message(STATUS "Linking with detected secp256k1 library: ${SECP256K1_LIBRARIES}")
    else()
        # No valid secp256k1 library found
        message(WARNING "secp256k1 claimed available but no library found - disabling")
        set(HAVE_SECP256K1 OFF)
    endif()
endif()

# Update crypto backend status after linking validation
set(HAVE_CRYPTO_BACKEND OFF)
if(HAVE_NOSCRYPT OR HAVE_SECP256K1)
    set(HAVE_CRYPTO_BACKEND ON)
endif()

# Final check for crypto backend availability
if(NOT HAVE_CRYPTO_BACKEND)
    if(WIN32)
        # On Windows, gracefully disable crypto features if no backend available
        message(WARNING "No cryptography backend available on Windows - building with limited functionality")
        message(STATUS "Consider installing secp256k1 via: vcpkg install secp256k1")
    else()
        message(WARNING "No cryptography backend available - building with limited functionality")
    endif()
endif()

# Generate feature detection header after all validation is complete
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/nostr_features.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/nostr_features.h"
    @ONLY
)

target_link_libraries(nostr ${NOSTR_LINK_LIBRARIES})
target_link_libraries(nostr_static ${NOSTR_LINK_LIBRARIES})

target_compile_options(nostr PRIVATE ${CJSON_CFLAGS_OTHER} ${SECP256K1_CFLAGS_OTHER} ${LIBWEBSOCKETS_CFLAGS_OTHER} ${NOSCRYPT_CFLAGS_OTHER})
target_compile_options(nostr_static PRIVATE ${CJSON_CFLAGS_OTHER} ${SECP256K1_CFLAGS_OTHER} ${LIBWEBSOCKETS_CFLAGS_OTHER} ${NOSCRYPT_CFLAGS_OTHER})

set_target_properties(nostr PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME nostr
)

set_target_properties(nostr_static PROPERTIES
    OUTPUT_NAME nostr
)

enable_testing()
add_subdirectory(tests)
add_subdirectory(examples)

install(TARGETS nostr nostr_static
    EXPORT libnostr-c-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/ DESTINATION include)

install(EXPORT libnostr-c-targets
    FILE libnostr-c-targets.cmake
    NAMESPACE libnostr-c::
    DESTINATION lib/cmake/libnostr-c
)

configure_file(libnostr-c.pc.in libnostr-c.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/libnostr-c.pc DESTINATION lib/pkgconfig)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/libnostr-c-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/libnostr-c-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/libnostr-c-config.cmake"
    INSTALL_DESTINATION lib/cmake/libnostr-c
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/libnostr-c-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/libnostr-c-config-version.cmake"
    DESTINATION lib/cmake/libnostr-c
)