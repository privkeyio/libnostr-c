# libnostr-c

[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL%20v2.1-blue.svg)](https://www.gnu.org/licenses/lgpl-2.1)
[![C99](https://img.shields.io/badge/C-99-blue.svg)](https://en.wikipedia.org/wiki/C99)

*A lightweight, portable C library for the Nostr protocol with native Lightning Network integration*

## What is libnostr-c?
A high-performance C implementation of the Nostr protocol built for efficiency and minimal dependencies. libnostr-c provides core event management, modern NIP-44 encryption powered by noscrypt, Lightning zaps, WebSocket relay communication, and complete relay-side protocol support. Designed for both client applications and relay implementations, with a focus on security, portability, and embedded systems.

## API Example
```c
// Client-side
nostr_init();
nostr_keypair_generate();
nostr_event_create();
nostr_event_sign();
nostr_nip44_encrypt();
nostr_relay_connect();

// Relay-side (for relay implementations)
nostr_client_msg_parse();
nostr_filter_matches();
nostr_event_validate_full();
nostr_deletion_authorized();
nostr_relay_msg_serialize();
nostr_relay_info_serialize();
```

## Motivation
Building nostr applications in C requires reliable, efficient cryptographic operations and protocol handling. libnostr-c provides a complete implementation with modern NIP-44 encryption, Lightning integration, and minimal resource requirements. Built with security-first design principles and optimized for both desktop and embedded systems.

## Platform Support
The following table lists supported platforms and cryptographic backends:

| Platform | Crypto Backend | Notes | CI Status |
| -------- | -------------- | ----- | --------- |
| Linux    | noscrypt, secp256k1 | GCC/Clang | ✅ Tested |
| macOS    | noscrypt, secp256k1 | Clang | ✅ Tested |
| Windows  | noscrypt, secp256k1 | MSVC | ✅ Tested |
| ESP-IDF  | noscrypt, mbedtls | ESP32/S2/S3/C3/C6, v5.0+ | ✅ Tested |

## Getting started
Please use the following links to obtain packages and extended documentation.

[__Documentation__](docs/API.md)  
[__Examples__](examples/)  
[__Performance Analysis__](docs/PERFORMANCE.md)  

### Super quick start
Prerequisites:
- CMake 3.16+, C99 compiler, OpenSSL
- secp256k1, libcjson, libwebsockets (see [BUILDING.md](docs/BUILDING.md))

```shell
git clone https://github.com/privkeyio/libnostr-c.git
cd libnostr-c
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

For detailed installation instructions, dependency management, and platform-specific setup, see [docs/BUILDING.md](docs/BUILDING.md).

## Notes
#### Builds
Automated builds and releases are available through GitHub Actions CI/CD.

#### Features
libnostr-c supports modular compilation - build only what you need:
- Core NIPs (01, 02, 13, 19, 57) enabled by default
- Optional NIPs (04, 09, 11, 17, 40, 44, 47, 59) via feature flags
- NIP-11 relay information document for serving relay metadata
- Relay protocol support for building relay implementations
- Modern noscrypt backend provides NIP-44 encryption
- Fallback to secp256k1 for basic operations

## Projects Using libnostr-c

- [keep-esp32](https://github.com/privkeyio/keep-esp32) - Air-gapped ESP32-S3 FROST threshold signing device with Nostr DKG coordination
- [vain](https://github.com/privkeyio/vain) - High-performance vanity Nostr public key miner

## License
The software in this repository is licensed under MIT. See the [LICENSE](LICENSE) file for details.

## Acknowledgments
This project is powered by [noscrypt](https://github.com/VnUgE/noscrypt) for high-performance cryptographic operations and NIP-44 encryption.

