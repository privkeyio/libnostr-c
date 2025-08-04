# libnostr-c

[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL%20v2.1-blue.svg)](https://www.gnu.org/licenses/lgpl-2.1)
[![C99](https://img.shields.io/badge/C-99-blue.svg)](https://en.wikipedia.org/wiki/C99)

*A lightweight, portable C library for the Nostr protocol with native Lightning Network integration*

## What is libnostr-c?
A high-performance C implementation of the Nostr protocol built for efficiency and minimal dependencies. libnostr-c provides core event management, modern NIP-44 encryption powered by noscrypt, Lightning zaps, and WebSocket relay communication. Designed for embedded systems and Bitcoin/Lightning integrations with a focus on security and portability.

## API Example
```c
nostr_init();
nostr_keypair_generate();
nostr_event_create();
nostr_event_sign();
nostr_nip44_encrypt();
nostr_nip44_decrypt();
nostr_relay_connect();
... extended functions
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
- Optional NIPs (04, 17, 44, 47, 59) via feature flags
- Modern noscrypt backend provides NIP-44 encryption
- Fallback to secp256k1 for basic operations

## License
The software in this repository is licensed under the GNU LGPL version 2.1 (or any later version). See the [LICENSE](LICENSE) file for details.

## Acknowledgments
This project is powered by [noscrypt](https://github.com/VnUgE/noscrypt) for high-performance cryptographic operations and NIP-44 encryption.

