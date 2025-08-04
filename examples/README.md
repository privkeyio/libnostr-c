# libnostr-c Examples

This directory contains practical examples demonstrating how to use libnostr-c for various Nostr protocol operations.

## Building Examples

The examples are built automatically when you build the main project with the `BUILD_EXAMPLES` option:

```bash
mkdir build && cd build
cmake -DBUILD_EXAMPLES=ON ..
make
```

Alternatively, you can build individual examples:

```bash
gcc -o basic_event basic_event.c -lnostr -lsecp256k1 -lcjson -lwebsockets
```

## Examples Overview

### 1. basic_event.c - Event Creation and Signing

**Purpose**: Demonstrates the fundamental operations of creating, signing, and verifying Nostr events.

**What it shows**:
- Key generation and format conversion
- Event creation with content and tags
- Event ID computation
- Digital signing and verification
- JSON serialization

**Usage**:
```bash
./basic_event
```

**Output**: Creates a sample text note event, displays its properties, and verifies the signature.

---

### 2. key_management.c - Cryptographic Key Operations

**Purpose**: Comprehensive demonstration of key generation, format conversion, and validation.

**What it shows**:
- Generating new keypairs
- Converting between hex and bech32 formats (npub/nsec)
- Event ID to note format conversion
- Round-trip conversion validation

**Usage**:
```bash
./key_management
```

**Output**: Shows various key formats and conversions with test vectors.

---

### 3. relay_client.c - Basic Relay Connection

**Purpose**: Shows how to connect to a Nostr relay and subscribe to events.

**What it shows**:
- Relay connection establishment
- Connection state monitoring
- Event subscription with filters
- Basic event handling
- Graceful disconnection

**Usage**:
```bash
./relay_client
```

**Output**: Connects to relay.damus.io and displays received events.

---

### 4. publish_note.c - Publishing Events to Relays

**Purpose**: Demonstrates publishing a user-provided message to multiple Nostr relays.

**What it shows**:
- Multi-relay publishing
- Event confirmation handling
- Error handling and retry logic
- Message callbacks for relay responses

**Usage**:
```bash
./publish_note "Hello, Nostr!"
```

**Output**: Publishes your message to multiple relays and shows confirmation.

---

### 5. subscribe_events.c - Advanced Event Subscription

**Purpose**: Advanced example showing different subscription patterns and real-time event monitoring.

**What it shows**:
- Multiple subscription types (historical and live)
- Event filtering by kind, tags, and time
- Real-time event display
- Subscription management
- Signal handling for graceful shutdown

**Usage**:
```bash
./subscribe_events [relay_url]
```

**Output**: Shows different types of events from the relay in real-time.

---

### 6. zap_example.c - Lightning Zaps (NIP-57)

**Purpose**: Demonstrates creating and verifying Lightning zap requests and receipts.

**What it shows**:
- Zap request creation with amount and recipient
- LNURL integration
- Zap receipt verification
- Multi-relay zap publishing

**Usage**:
```bash
# Create a zap request
./zap_example create 21000 npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6 lnurl1dp68gurn8ghj7um5v93kketj9ehx2amn9uh8wetvdskkkmn0wahz7mrww4excup0dajx2mrv92x9xp -m "Great work!"

# Verify a zap receipt
./zap_example verify receipt.json request.json server_pubkey
```

**Output**: Creates zap request JSON or verifies zap receipt validity.

## Common Patterns

### Error Handling

All examples demonstrate proper error handling:

```c
if (nostr_init() != NOSTR_OK) {
    fprintf(stderr, "Failed to initialize libnostr-c\n");
    return 1;
}

// Always clean up on exit
nostr_cleanup();
```

### Memory Management

Examples show proper resource cleanup:

```c
// Events
nostr_event* event;
nostr_event_create(&event);
// ... use event ...
nostr_event_destroy(event);

// Relays
nostr_relay* relay;
nostr_relay_create(&relay, url);
// ... use relay ...
nostr_relay_disconnect(relay);
nostr_relay_destroy(relay);
```

### Async Operations

Relay operations are asynchronous and use callbacks:

```c
void relay_callback(nostr_relay* relay, nostr_relay_state state, void* user_data) {
    switch (state) {
        case NOSTR_RELAY_CONNECTED:
            printf("Connected!\n");
            break;
        // ... handle other states
    }
}

nostr_relay_connect(relay, relay_callback, NULL);
```

## Integration Examples

### Bitcoin/Lightning Integration

For Bitcoin and Lightning Network integration examples, see:
- `zap_example.c` for NIP-57 zap implementation
- [Integration Guide](../docs/INTEGRATION.md) for detailed patterns

### Production Usage

For production applications, consider:
- **Key persistence**: Store keys securely, don't generate new ones each time
- **Relay management**: Implement relay selection and failover logic
- **Event deduplication**: Handle duplicate events from multiple relays
- **Rate limiting**: Respect relay limits and implement backoff
- **Error recovery**: Implement reconnection logic for network failures

## Building Your Own Application

1. **Start with basic_event.c**: Understand event creation and signing
2. **Study relay_client.c**: Learn relay connection patterns
3. **Review subscribe_events.c**: Understand event filtering and handling
4. **Check zap_example.c**: See advanced protocol features
5. **Read the [API Reference](../docs/API.md)**: Full function documentation

## Dependencies

All examples require:
- libnostr-c (this library)
- libsecp256k1
- libcjson
- libwebsockets

## Testing

You can test the examples against live relays:

```bash
# Test basic functionality
./basic_event

# Test with live relay
./relay_client

# Test event publishing
./publish_note "Testing libnostr-c"

# Test live subscription
./subscribe_events wss://relay.nostr.band
```

## Troubleshooting

**Connection Issues**:
- Check your internet connection
- Verify the relay URL is correct
- Some relays may have rate limits or restrictions

**Build Issues**:
- Ensure all dependencies are installed
- Check that libnostr-c is properly installed
- Verify CMake configuration

**Runtime Errors**:
- Check error messages from `nostr_error_string()`
- Ensure proper cleanup on exit
- Verify event structure before signing

For more help, see the [main documentation](../docs/) or open an issue on GitHub.