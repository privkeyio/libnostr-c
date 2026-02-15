# Changelog

## [0.2.0] - 2026-02-14

### Security
- Harden JSON escaping with RFC 8259 control character support
- Add secure_wipe on all crypto key error paths (secp256k1 keypair, NIP-44 nc_secret/hmac_key)
- Fix integer overflow in tag arena allocator and tag size calculations
- Replace strcmp with constant-time comparison for session IDs and zap pubkeys
- Validate params_json and filters_json as valid JSON before insertion
- Fix permissions array leak in expired session cleanup
- Fix permission reset time drift

### Changed
- Simplify NIP-44 encrypt/decrypt cleanup paths
- Extract session lookup helper to reduce duplication

## [0.1.6] - 2026-01-27

### Added
- NIP-50 search filter support
- NIP-51 Lists support
- NIP-26 delegated event signing support
- NIP-49 private key encryption support
- NIP-18 repost support and `nostr_filter_clone()`
- NIP-06 BIP39 mnemonic key derivation support
- NIP-05 DNS-based identity verification
- NIP-65 relay list metadata support
- NIP-21 URI scheme support
- NIP-45 COUNT message support
- NIP-10 and NIP-25 support

### Fixed
- NIP-44 decrypt MAC verification and padding calculation

### Changed
- Split test_relay_protocol.c into logical modules

## [0.1.5] - 2026-01-14

### Fixed
- Use NCSignDigest/NCVerifyDigest for event signing (event ID is already a SHA256 digest)
- Windows threading race condition in context initialization using InitOnceExecuteOnce
- Memory corruption in NIP-13 nonce tag updates (use arena allocation)
- Memory leaks in NIP-44 decrypt error paths

## [0.1.4] - 2026-01-11

### Added
- NIP-46 (Nostr Connect) remote signer support
- Public hex utilities: `nostr_hex_decode()`, `nostr_hex_encode()`
- NIP-13 proof-of-work support for ESP-IDF builds

### Changed
- Removed unused OpenSSL SHA header from nip13.c

## [0.1.3] - 2026-01-11

### Added
- ESP32-S3 CI build support
- Relay protocol sources to ESP-IDF build

### Changed
- Refactored relay_protocol.c into modular files for better maintainability

### Fixed
- Wrapped escape_json_string in ifndef NOSTR_FEATURE_JSON_ENHANCED for conditional compilation

## [0.1.2] - 2025-12-27

### Added
- ESP-IDF component support for ESP32 development
- mbedtls cryptographic backend support for ESP32 platform
- Zig build system support
- NIP-11 relay information document support
- NIP-09 event deletion support
- NIP-01 relay-side protocol support
- Relay accessor functions for improved API ergonomics

### Fixed
- NIP-44 MAC verification
- NIP-01 double-escaping in serialize_for_id

## [0.1.1] - 2025-08-03

### Initial Release

#### Core Protocol Support
- Basic event creation, serialization, and parsing (NIP-01)
- WebSocket relay communication (NIP-02)  
- Event metadata support (NIP-13)
- Bech32 encoding/decoding for npub/nsec keys (NIP-19)
- Lightning Zaps support (NIP-57)

#### Optional NIPs (via feature flags)
- Encrypted direct messages (NIP-04)
- Private direct messages (NIP-17)
- Modern NIP-44 encryption powered by noscrypt
- Authentication of clients to relays (NIP-47)
- Lightning zap receipts (NIP-59)

#### Cryptographic Operations
- Dual crypto backend support: noscrypt and secp256k1
- High-performance NIP-44 encryption/decryption
- Key generation, signing, and verification
- Security-first design principles

#### Platform & Build Support
- Cross-platform support (Linux, macOS, Windows)
- CMake build system with pkg-config support
- Modular compilation - build only what you need
- C99 compliance for maximum portability
- Optimized for both desktop and embedded systems

#### Development & Testing
- Comprehensive test suite with Unity framework
- Thread-safe relay connections
- Example applications and documentation
- Performance analysis and benchmarking
- Automated CI/CD with GitHub Actions