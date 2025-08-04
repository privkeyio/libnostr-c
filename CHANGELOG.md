# Changelog

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