# Thread Safety Guidelines

## Overview

libnostr-c is designed to be thread-safe for most operations. This document provides guidelines for safe concurrent usage.

## Thread Safety Guarantees

### Always Thread-Safe (Reentrant)
These functions can be called safely from multiple threads simultaneously:

- **Key Operations**: `nostr_key_generate()`, `nostr_key_from_hex()`, `nostr_key_to_hex()`
- **Signing/Verification**: `nostr_event_sign()`, `nostr_event_verify()`  
- **Encryption**: All NIP-04 and NIP-44 encryption/decryption functions
- **Event Parsing**: `nostr_event_from_json()`, `nostr_event_to_json()`
- **Utilities**: `nostr_bech32_encode()`, `nostr_bech32_decode()`
- **NIP Functions**: All NIP-13, NIP-17, NIP-59 functions

### Internally Synchronized
These functions use internal locking and can be called from multiple threads:

- **Initialization**: `nostr_init()`, `nostr_init_with_config()`, `nostr_cleanup()`
- **Configuration**: `nostr_config_get_current()`, `nostr_config_update()`, `nostr_config_set_callback()`
- **NIP-47 Sessions**: All session management functions

### Not Thread-Safe
These require external synchronization or separate instances per thread:

- **Relay Connections**: Each thread should use its own `nostr_relay` instance
- **Mutable Event Objects**: Don't modify the same event from multiple threads

## Usage Patterns

### Single Initialization
```c
// Call once at program startup
if (nostr_init() != NOSTR_OK) {
    // Handle error
}

// Later calls from any thread are safe and return immediately
nostr_init(); // Safe to call again
```

### Per-Thread Resources
```c
// Each thread should have its own relay connection
void* worker_thread(void* arg) {
    nostr_relay* relay = nostr_relay_new("wss://relay.example.com");
    
    // Use relay in this thread only
    nostr_relay_connect(relay);
    // ...
    
    nostr_relay_free(relay);
    return NULL;
}
```

### Shared Configuration
```c
// Safe to update config from any thread
nostr_config config;
nostr_config_get_defaults(&config);
config.max_sessions = 200;
nostr_config_update(&config); // Internally synchronized

// Safe to read from any thread
const nostr_config* current = nostr_config_get_current();
```

### Concurrent Key Operations
```c
// Multiple threads can generate keys simultaneously
void* key_worker(void* arg) {
    for (int i = 0; i < 1000; i++) {
        nostr_privkey privkey;
        nostr_key pubkey;
        
        // Thread-safe key generation
        nostr_key_generate(&privkey, &pubkey);
        
        // Process keys...
    }
    return NULL;
}
```

## Best Practices

1. **Initialize Once**: Call `nostr_init()` once at program startup
2. **Separate Relay Instances**: Use one relay connection per thread
3. **Immutable Events**: Treat events as immutable after creation
4. **Configuration Updates**: Use the provided config API for thread-safe updates
5. **Memory Management**: Each thread manages its own allocated objects

## Common Pitfalls

### Sharing Relay Connections (Don't)
```c
// DON'T: Share relay between threads
nostr_relay* shared_relay = nostr_relay_new("wss://relay.example.com");

void* thread1(void* arg) {
    nostr_relay_publish(shared_relay, event1); // Race condition!
}

void* thread2(void* arg) {
    nostr_relay_publish(shared_relay, event2); // Race condition!
}
```

### Per-Thread Relay Connections (Do)
```c
// DO: Create separate relay per thread
void* thread1(void* arg) {
    nostr_relay* relay = nostr_relay_new("wss://relay.example.com");
    nostr_relay_publish(relay, event1); // Safe
    nostr_relay_free(relay);
}

void* thread2(void* arg) {
    nostr_relay* relay = nostr_relay_new("wss://relay.example.com");
    nostr_relay_publish(relay, event2); // Safe
    nostr_relay_free(relay);
}
```

### Modifying Shared Events (Don't)
```c
// DON'T: Modify same event from multiple threads
nostr_event* shared_event = create_event();

void* thread1(void* arg) {
    nostr_event_add_tag(shared_event, "tag1", "value1"); // Race condition!
}

void* thread2(void* arg) {
    nostr_event_add_tag(shared_event, "tag2", "value2"); // Race condition!
}
```

### Immutable Event Usage (Do)
```c
// DO: Create events per thread or treat as immutable
void* thread1(void* arg) {
    nostr_event* event = create_event();
    nostr_event_add_tag(event, "tag1", "value1"); // Safe - thread-local
    // Use event...
    nostr_event_free(event);
}
```

## Testing Thread Safety

Use the provided test suite to verify thread safety:

```bash
gcc -o test_thread_safety tests/test_thread_safety.c -lnostr -lpthread
./test_thread_safety
```

The test suite verifies:
- Concurrent initialization
- Concurrent key generation 
- Configuration callback safety
- Session management under load