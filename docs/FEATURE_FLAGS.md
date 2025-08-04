# libnostr-c Feature Flags

libnostr-c supports modular compilation through CMake feature flags, allowing you to build only the functionality you need.

## Quick Start

### Minimal Build (Basic Events + Keys)
```bash
cmake -DNOSTR_FEATURE_CRYPTO_SECP256K1=ON \
      -DNOSTR_FEATURE_CRYPTO_NOSCRYPT=OFF \
      .
```

### Standard Build (with NIPs 13, 57 + Relay)
```bash
cmake . # Uses sensible defaults
```

### Full Build (All Features)
```bash
cmake -DNOSTR_FEATURE_ALL_NIPS=ON .
```

## Available Feature Flags

### Core Features (Always Enabled)
- `NOSTR_FEATURE_STD` - Standard library support
- `NOSTR_FEATURE_EVENTS` - Event creation and management
- `NOSTR_FEATURE_KEYS` - Key generation and cryptography
- `NOSTR_FEATURE_ENCODING` - Bech32/hex encoding

### NIP Features (Optional)
- `NOSTR_FEATURE_NIP04` - Legacy Encrypted Direct Messages (deprecated, requires noscrypt)
- `NOSTR_FEATURE_NIP13` - Proof of Work (ON by default)
- `NOSTR_FEATURE_NIP17` - Private Direct Messages (requires noscrypt)
- `NOSTR_FEATURE_NIP44` - Encrypted Payloads v2 (requires noscrypt)
- `NOSTR_FEATURE_NIP47` - Nostr Wallet Connect (requires noscrypt)
- `NOSTR_FEATURE_NIP57` - Lightning Zaps (ON by default)
- `NOSTR_FEATURE_NIP59` - Gift Wrap (requires noscrypt)

### Optional Enhancements
- `NOSTR_FEATURE_RELAY` - Relay communication (ON by default, requires libwebsockets)
- `NOSTR_FEATURE_HD_KEYS` - HD key derivation (requires noscrypt)
- `NOSTR_FEATURE_JSON_ENHANCED` - Enhanced JSON handling (ON by default, requires cJSON)
- `NOSTR_FEATURE_THREADING` - Multi-threaded operations (ON by default)

### Cryptography Backends
- `NOSTR_FEATURE_CRYPTO_NOSCRYPT` - Use noscrypt (preferred, OFF by default if not available)
- `NOSTR_FEATURE_CRYPTO_SECP256K1` - Use secp256k1 (fallback, ON by default)

### Meta Options
- `NOSTR_FEATURE_ALL_NIPS` - Enable all NIPs (overrides individual NIP flags)

## Dependencies

| Feature | Required Dependencies |
|---------|----------------------|
| Core | OpenSSL, secp256k1 OR noscrypt |
| Relay | libwebsockets |
| JSON Enhanced | cJSON |
| NIP-04/17/44/47/59 | noscrypt |
| HD Keys | noscrypt |

## Runtime Detection

```c
#include <nostr_features.h>

// Check specific NIPs
if (nostr_feature_nip_supported(44)) {
    // NIP-44 is available
}

// Check optional features  
if (nostr_feature_relay_available()) {
    // Relay functionality available
}

// Get feature summary
printf("Features: %s\n", nostr_feature_list_enabled());
printf("Crypto: %s\n", nostr_feature_crypto_backend_info());
```

## Build Size Impact

| Configuration | Approximate Size Reduction |
|---------------|---------------------------|
| Minimal (no NIPs) | ~40% smaller |
| No Relay | ~15% smaller |
| No HD Keys | ~10% smaller |
| secp256k1 only | ~20% smaller |

## Breaking Changes

When features are disabled:
- Disabled functions return `NOSTR_ERR_NOT_SUPPORTED`
- Examples/tests for disabled features are not built
- Some header definitions may not be available

## Migration Guide

### From Previous Versions
1. No code changes needed - all features enabled by default maintain compatibility
2. Add feature detection if you want to support multiple build configurations:
   ```c
   if (nostr_feature_nip_supported(44)) {
       // Use NIP-44
   } else {
       // Fallback or error
   }
   ```

### For Library Distributors
Consider providing multiple packages:
- `libnostr-c-minimal` - Core functionality only
- `libnostr-c` - Standard build
- `libnostr-c-full` - All features

## Examples

See `examples/` directory for feature-aware examples that demonstrate graceful degradation when features are unavailable.