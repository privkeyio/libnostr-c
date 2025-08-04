# libnostr-c API Reference

## Overview

libnostr-c provides a comprehensive C implementation of the Nostr protocol. This document describes all public APIs available in the library.

## Initialization

### nostr_init()
```c
nostr_error_t nostr_init(void);
```
Initialize the libnostr-c library. Must be called before using any other functions.

**Returns**: `NOSTR_OK` on success, error code otherwise.

### nostr_cleanup()
```c
void nostr_cleanup(void);
```
Clean up the libnostr-c library. Should be called when done using the library.

## Error Handling

### nostr_error_t
```c
typedef enum {
    NOSTR_OK = 0,
    NOSTR_ERR_INVALID_KEY,
    NOSTR_ERR_INVALID_EVENT,
    NOSTR_ERR_INVALID_SIGNATURE,
    NOSTR_ERR_MEMORY,
    NOSTR_ERR_JSON_PARSE,
    NOSTR_ERR_ENCODING,
    NOSTR_ERR_CONNECTION,
    NOSTR_ERR_PROTOCOL,
    NOSTR_ERR_NOT_FOUND,
    NOSTR_ERR_TIMEOUT,
    NOSTR_ERR_INVALID_PARAM
} nostr_error_t;
```
Error codes returned by libnostr-c functions.

### nostr_error_string()
```c
const char* nostr_error_string(nostr_error_t error);
```
Get human-readable error message for an error code.

## Key Management

### Data Structures

#### nostr_key
```c
typedef struct nostr_key {
    uint8_t data[NOSTR_PUBKEY_SIZE];
} nostr_key;
```
Public key structure (32 bytes).

#### nostr_privkey
```c
typedef struct nostr_privkey {
    uint8_t data[NOSTR_PRIVKEY_SIZE];
} nostr_privkey;
```
Private key structure (32 bytes).

### Functions

#### nostr_key_generate()
```c
nostr_error_t nostr_key_generate(nostr_privkey* privkey, nostr_key* pubkey);
```
Generate a new cryptographically secure keypair.

**Parameters**:
- `privkey`: Output private key
- `pubkey`: Output public key

**Returns**: `NOSTR_OK` on success, error code otherwise.

#### nostr_key_from_hex()
```c
nostr_error_t nostr_key_from_hex(const char* hex, nostr_key* key);
```
Convert hex string to public key.

**Parameters**:
- `hex`: 64-character hex string
- `key`: Output public key

**Returns**: `NOSTR_OK` on success, `NOSTR_ERR_ENCODING` on invalid hex.

#### nostr_key_to_hex()
```c
nostr_error_t nostr_key_to_hex(const nostr_key* key, char* hex, size_t hex_size);
```
Convert public key to hex string.

**Parameters**:
- `key`: Input public key
- `hex`: Output buffer (minimum 65 bytes)
- `hex_size`: Size of output buffer

**Returns**: `NOSTR_OK` on success, `NOSTR_ERR_INVALID_PARAM` if buffer too small.

#### nostr_key_to_bech32()
```c
nostr_error_t nostr_key_to_bech32(const nostr_key* key, const char* prefix, 
                                  char* bech32, size_t bech32_size);
```
Convert public key to bech32 format.

**Parameters**:
- `key`: Input public key
- `prefix`: Bech32 prefix (e.g., "npub")
- `bech32`: Output buffer
- `bech32_size`: Size of output buffer

**Returns**: `NOSTR_OK` on success, error code otherwise.

#### nostr_key_from_bech32()
```c
nostr_error_t nostr_key_from_bech32(const char* bech32, nostr_key* key);
```
Convert bech32 string to public key.

**Parameters**:
- `bech32`: Input bech32 string
- `key`: Output public key

**Returns**: `NOSTR_OK` on success, `NOSTR_ERR_ENCODING` on invalid bech32.

## Event Management

### Data Structures

#### nostr_tag
```c
typedef struct nostr_tag {
    char** values;
    size_t count;
} nostr_tag;
```
Event tag structure containing array of string values.

#### nostr_event
```c
typedef struct nostr_event {
    uint8_t id[NOSTR_ID_SIZE];
    nostr_key pubkey;
    int64_t created_at;
    uint16_t kind;
    nostr_tag* tags;
    size_t tags_count;
    char* content;
    uint8_t sig[NOSTR_SIG_SIZE];
} nostr_event;
```
Nostr event structure containing all event data.

### Functions

#### nostr_event_create()
```c
nostr_error_t nostr_event_create(nostr_event** event);
```
Create a new event structure.

**Parameters**:
- `event`: Output event pointer

**Returns**: `NOSTR_OK` on success, `NOSTR_ERR_MEMORY` on allocation failure.

#### nostr_event_destroy()
```c
void nostr_event_destroy(nostr_event* event);
```
Destroy an event and free all associated memory.

**Parameters**:
- `event`: Event to destroy

#### nostr_event_set_content()
```c
nostr_error_t nostr_event_set_content(nostr_event* event, const char* content);
```
Set event content string.

**Parameters**:
- `event`: Event to modify
- `content`: Content string to set

**Returns**: `NOSTR_OK` on success, `NOSTR_ERR_MEMORY` on allocation failure.

#### nostr_event_add_tag()
```c
nostr_error_t nostr_event_add_tag(nostr_event* event, const char** values, size_t count);
```
Add a tag to an event.

**Parameters**:
- `event`: Event to modify
- `values`: Array of tag values
- `count`: Number of values

**Returns**: `NOSTR_OK` on success, `NOSTR_ERR_MEMORY` on allocation failure.

#### nostr_event_compute_id()
```c
nostr_error_t nostr_event_compute_id(nostr_event* event);
```
Compute event ID (SHA256 hash) according to NIP-01.

**Parameters**:
- `event`: Event to compute ID for

**Returns**: `NOSTR_OK` on success, error code otherwise.

#### nostr_event_sign()
```c
nostr_error_t nostr_event_sign(nostr_event* event, const nostr_privkey* privkey);
```
Sign an event with a private key.

**Parameters**:
- `event`: Event to sign
- `privkey`: Private key for signing

**Returns**: `NOSTR_OK` on success, `NOSTR_ERR_INVALID_SIGNATURE` on failure.

#### nostr_event_verify()
```c
nostr_error_t nostr_event_verify(const nostr_event* event);
```
Verify event signature.

**Parameters**:
- `event`: Event to verify

**Returns**: `NOSTR_OK` if valid, `NOSTR_ERR_INVALID_SIGNATURE` if invalid.

#### nostr_event_to_json()
```c
nostr_error_t nostr_event_to_json(const nostr_event* event, char** json);
```
Serialize event to JSON string.

**Parameters**:
- `event`: Event to serialize
- `json`: Output JSON string (caller must free)

**Returns**: `NOSTR_OK` on success, error code otherwise.

#### nostr_event_from_json()
```c
nostr_error_t nostr_event_from_json(const char* json, nostr_event** event);
```
Parse event from JSON string.

**Parameters**:
- `json`: Input JSON string
- `event`: Output event pointer

**Returns**: `NOSTR_OK` on success, `NOSTR_ERR_JSON_PARSE` on invalid JSON.

## Relay Communication

### Data Structures

#### nostr_relay_state
```c
typedef enum {
    NOSTR_RELAY_DISCONNECTED = 0,
    NOSTR_RELAY_CONNECTING,
    NOSTR_RELAY_CONNECTED,
    NOSTR_RELAY_ERROR
} nostr_relay_state;
```
Relay connection states.

#### nostr_relay
```c
typedef struct nostr_relay {
    char* url;
    nostr_relay_state state;
    void* ws_handle;
    void* user_data;
    nostr_message_callback message_callback;
    void* message_user_data;
} nostr_relay;
```
Relay connection structure.

### Callback Types

#### nostr_relay_callback
```c
typedef void (*nostr_relay_callback)(struct nostr_relay* relay, 
                                    nostr_relay_state state, void* user_data);
```
Callback for relay state changes.

#### nostr_event_callback
```c
typedef void (*nostr_event_callback)(const nostr_event* event, void* user_data);
```
Callback for received events.

#### nostr_message_callback
```c
typedef void (*nostr_message_callback)(const char* message_type, 
                                      const char* data, void* user_data);
```
Callback for relay protocol messages.

### Functions

#### nostr_relay_create()
```c
nostr_error_t nostr_relay_create(nostr_relay** relay, const char* url);
```
Create a new relay connection.

**Parameters**:
- `relay`: Output relay pointer
- `url`: WebSocket URL (e.g., "wss://relay.damus.io")

**Returns**: `NOSTR_OK` on success, error code otherwise.

#### nostr_relay_destroy()
```c
void nostr_relay_destroy(nostr_relay* relay);
```
Destroy a relay connection and free resources.

**Parameters**:
- `relay`: Relay to destroy

#### nostr_relay_connect()
```c
nostr_error_t nostr_relay_connect(nostr_relay* relay, nostr_relay_callback callback, 
                                 void* user_data);
```
Connect to a relay.

**Parameters**:
- `relay`: Relay instance
- `callback`: State change callback
- `user_data`: User data for callback

**Returns**: `NOSTR_OK` on success, `NOSTR_ERR_CONNECTION` on failure.

#### nostr_relay_disconnect()
```c
nostr_error_t nostr_relay_disconnect(nostr_relay* relay);
```
Disconnect from a relay.

**Parameters**:
- `relay`: Relay instance

**Returns**: `NOSTR_OK` on success, error code otherwise.

#### nostr_publish_event()
```c
nostr_error_t nostr_publish_event(nostr_relay* relay, const nostr_event* event);
```
Publish an event to a relay.

**Parameters**:
- `relay`: Relay instance
- `event`: Event to publish

**Returns**: `NOSTR_OK` on success, error code otherwise.

#### nostr_subscribe()
```c
nostr_error_t nostr_subscribe(nostr_relay* relay, const char* subscription_id,
                             const char* filters_json, nostr_event_callback callback,
                             void* user_data);
```
Subscribe to events matching filters.

**Parameters**:
- `relay`: Relay instance
- `subscription_id`: Unique subscription ID
- `filters_json`: JSON filters (NIP-01 format)
- `callback`: Event callback
- `user_data`: User data for callback

**Returns**: `NOSTR_OK` on success, error code otherwise.

#### nostr_relay_unsubscribe()
```c
nostr_error_t nostr_relay_unsubscribe(nostr_relay* relay, const char* subscription_id);
```
Unsubscribe from a subscription.

**Parameters**:
- `relay`: Relay instance
- `subscription_id`: Subscription ID to cancel

**Returns**: `NOSTR_OK` on success, error code otherwise.

## Lightning Zaps (NIP-57)

### Functions

#### nostr_zap_create_request()
```c
nostr_error_t nostr_zap_create_request(nostr_event** event, uint64_t amount,
                                      const nostr_key* recipient, const char* lnurl,
                                      const char* content, const char** relays,
                                      size_t relays_count);
```
Create a zap request event (kind 9734).

**Parameters**:
- `event`: Output event pointer
- `amount`: Amount in millisats
- `recipient`: Recipient's public key
- `lnurl`: Recipient's LNURL
- `content`: Optional zap message
- `relays`: Array of relay URLs
- `relays_count`: Number of relays

**Returns**: `NOSTR_OK` on success, error code otherwise.

#### nostr_zap_validate_lnurl()
```c
nostr_error_t nostr_zap_validate_lnurl(const char* lnurl, char* nostr_pubkey, 
                                      bool* allows_nostr);
```
Validate an LNURL for zap support.

**Parameters**:
- `lnurl`: LNURL to validate
- `nostr_pubkey`: Output buffer for server's pubkey (optional, 33 bytes)
- `allows_nostr`: Output flag for nostr support (optional)

**Returns**: `NOSTR_OK` if valid, error code otherwise.

#### nostr_zap_parse_receipt()
```c
nostr_error_t nostr_zap_parse_receipt(const nostr_event* event, uint64_t* amount,
                                     char** bolt11, char* preimage,
                                     nostr_event** zap_request);
```
Parse zap receipt event (kind 9735).

**Parameters**:
- `event`: Input zap receipt event
- `amount`: Output amount in millisats (optional)
- `bolt11`: Output bolt11 invoice (optional, caller must free)
- `preimage`: Output preimage (optional, 64 bytes hex)
- `zap_request`: Output zap request event (optional, caller must free)

**Returns**: `NOSTR_OK` on success, error code otherwise.

#### nostr_zap_verify()
```c
nostr_error_t nostr_zap_verify(const nostr_event* receipt, const nostr_event* request,
                              const char* server_pubkey);
```
Verify a zap receipt against the original request.

**Parameters**:
- `receipt`: Zap receipt event (kind 9735)
- `request`: Original zap request event (kind 9734)
- `server_pubkey`: Expected server's nostr pubkey

**Returns**: `NOSTR_OK` if valid, error code otherwise.

## Bech32 Encoding

### Event IDs

#### nostr_event_id_to_bech32()
```c
nostr_error_t nostr_event_id_to_bech32(const uint8_t* id, char* bech32, size_t bech32_size);
```
Convert event ID to bech32 format (note).

#### nostr_event_id_from_bech32()
```c
nostr_error_t nostr_event_id_from_bech32(const char* bech32, uint8_t* id);
```
Convert bech32 string to event ID.

### Private Keys

#### nostr_privkey_to_bech32()
```c
nostr_error_t nostr_privkey_to_bech32(const nostr_privkey* privkey, char* bech32, 
                                     size_t bech32_size);
```
Convert private key to bech32 format (nsec).

#### nostr_privkey_from_bech32()
```c
nostr_error_t nostr_privkey_from_bech32(const char* bech32, nostr_privkey* privkey);
```
Convert bech32 string to private key.

## Constants

```c
#define NOSTR_PUBKEY_SIZE  32    // Public key size in bytes
#define NOSTR_PRIVKEY_SIZE 32    // Private key size in bytes
#define NOSTR_SIG_SIZE     64    // Signature size in bytes
#define NOSTR_ID_SIZE      32    // Event ID size in bytes
```

## Usage Patterns

### Basic Event Flow
```c
// Initialize library
nostr_init();

// Generate keys
nostr_privkey privkey;
nostr_key pubkey;
nostr_key_generate(&privkey, &pubkey);

// Create event
nostr_event* event;
nostr_event_create(&event);
event->kind = 1;
event->pubkey = pubkey;
nostr_event_set_content(event, "Hello, Nostr!");
nostr_event_compute_id(event);
nostr_event_sign(event, &privkey);

// Verify and serialize
nostr_event_verify(event);
char* json;
nostr_event_to_json(event, &json);

// Cleanup
free(json);
nostr_event_destroy(event);
nostr_cleanup();
```

### Relay Communication
```c
// Create and connect to relay
nostr_relay* relay;
nostr_relay_create(&relay, "wss://relay.damus.io");
nostr_relay_connect(relay, state_callback, NULL);

// Subscribe to events
nostr_subscribe(relay, "sub1", "{\"kinds\":[1]}", event_callback, NULL);

// Publish event
nostr_publish_event(relay, event);

// Cleanup
nostr_relay_disconnect(relay);
nostr_relay_destroy(relay);
```

## Error Handling Best Practices

Always check return values and handle errors appropriately:

```c
nostr_error_t err = nostr_event_create(&event);
if (err != NOSTR_OK) {
    fprintf(stderr, "Failed to create event: %s\n", nostr_error_string(err));
    return -1;
}
```

## Thread Safety

libnostr-c is not thread-safe. If using in a multi-threaded environment:
- Use separate library instances per thread, or
- Implement external synchronization around library calls

## Memory Management

- Always call `nostr_init()` before using the library
- Always call `nostr_cleanup()` when done
- Free all allocated strings returned by the library
- Use `nostr_event_destroy()` for events
- Use `nostr_relay_destroy()` for relays

For more examples and integration patterns, see the [examples directory](../examples/) and [integration guide](INTEGRATION.md).