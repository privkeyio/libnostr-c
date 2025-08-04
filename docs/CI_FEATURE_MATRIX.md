# Feature Flag Testing Matrix for CI

This document outlines the recommended CI test matrix for the libnostr-c feature flag system.

## Build Configurations

### Minimal Build (secp256k1 only)
```bash
cmake -DNOSTR_FEATURE_CRYPTO_NOSCRYPT=OFF \
      -DNOSTR_FEATURE_CRYPTO_SECP256K1=ON \
      -DNOSTR_FEATURE_NIP04=OFF \
      -DNOSTR_FEATURE_NIP17=OFF \
      -DNOSTR_FEATURE_NIP44=OFF \
      -DNOSTR_FEATURE_NIP47=OFF \
      -DNOSTR_FEATURE_NIP59=OFF \
      -DNOSTR_FEATURE_HD_KEYS=OFF \
      .
```

### Standard Build (with NIP-13, NIP-57)  
```bash
cmake -DNOSTR_FEATURE_CRYPTO_SECP256K1=ON \
      -DNOSTR_FEATURE_NIP13=ON \
      -DNOSTR_FEATURE_NIP57=ON \
      .
```

### Full Build (noscrypt + all features)
```bash
cmake -DNOSTR_FEATURE_CRYPTO_NOSCRYPT=ON \
      -DNOSTR_FEATURE_ALL_NIPS=ON \
      .
```

### Relay-only Build
```bash
cmake -DNOSTR_FEATURE_RELAY=ON \
      -DNOSTR_FEATURE_CRYPTO_SECP256K1=ON \
      .
```

## Test Matrix

| Configuration | Dependencies | Features Enabled | Use Case |
|---------------|--------------|------------------|----------|
| Minimal | secp256k1, openssl | Core events, keys | Embedded/constrained |
| Standard | secp256k1, openssl, libwebsockets, cjson | Core + NIP-13 + NIP-57 + Relay | Typical client |
| Full | noscrypt, secp256k1, openssl, libwebsockets, cjson | All NIPs | Advanced client |
| Relay-only | secp256k1, openssl, libwebsockets | Core + Relay | Relay implementation |

## GitHub Actions Example

```yaml
strategy:
  matrix:
    config:
      - name: "Minimal"
        cmake_flags: "-DNOSTR_FEATURE_CRYPTO_NOSCRYPT=OFF -DNOSTR_FEATURE_ALL_NIPS=OFF"
      - name: "Standard" 
        cmake_flags: "-DNOSTR_FEATURE_NIP13=ON -DNOSTR_FEATURE_NIP57=ON"
      - name: "Full"
        cmake_flags: "-DNOSTR_FEATURE_ALL_NIPS=ON"
```

## Runtime Feature Detection

All builds include runtime feature detection:

```c
#include <nostr_features.h>

if (nostr_feature_nip_supported(44)) {
    // Use NIP-44 functionality
}

printf("Enabled features: %s\n", nostr_feature_list_enabled());
printf("Crypto backend: %s\n", nostr_feature_crypto_backend_info());
```