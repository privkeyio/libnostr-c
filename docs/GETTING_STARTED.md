# Getting Started with libnostr-c

## Overview

libnostr-c is a lightweight C library that implements the Nostr protocol, providing tools for creating events, managing cryptographic keys, communicating with relays, and handling Lightning zaps.

## Installation

### Prerequisites

Before building libnostr-c, ensure you have the following dependencies:

- **CMake** (>= 3.10)
- **C99 compatible compiler** (GCC, Clang)
- **libsecp256k1** - Bitcoin's elliptic curve library
- **libcjson** - JSON parsing library
- **libwebsockets** - WebSocket client library

### Ubuntu/Debian Installation

```bash
sudo apt update
sudo apt install cmake build-essential
sudo apt install libsecp256k1-dev libcjson-dev libwebsockets-dev
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/privkeyio/libnostr-c.git
cd libnostr-c

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build the library
make

# Install system-wide (optional)
sudo make install
```

### Build Options

You can customize the build with these CMake options:

```bash
# Build shared library (default: static)
cmake -DBUILD_SHARED_LIBS=ON ..

# Include test suite
cmake -DBUILD_TESTS=ON ..

# Include example programs
cmake -DBUILD_EXAMPLES=ON ..

# Debug build
cmake -DCMAKE_BUILD_TYPE=Debug ..
```

## Basic Usage

### 1. Initialize the Library

```c
#include <nostr.h>

int main() {
    // Initialize the library
    if (nostr_init() != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c\n");
        return 1;
    }
    
    // Your code here...
    
    // Clean up
    nostr_cleanup();
    return 0;
}
```

### 2. Generate Keys

```c
nostr_privkey privkey;
nostr_key pubkey;

// Generate a new keypair
if (nostr_key_generate(&privkey, &pubkey) != NOSTR_OK) {
    fprintf(stderr, "Failed to generate keypair\n");
    return 1;
}

// Convert to hex for display
char pubkey_hex[65];
nostr_key_to_hex(&pubkey, pubkey_hex, sizeof(pubkey_hex));
printf("Public key: %s\n", pubkey_hex);

// Convert to bech32 format (npub)
char npub[100];
nostr_key_to_bech32(&pubkey, "npub", npub, sizeof(npub));
printf("npub: %s\n", npub);
```

### 3. Create and Sign an Event

```c
nostr_event* event;

// Create a new event
if (nostr_event_create(&event) != NOSTR_OK) {
    fprintf(stderr, "Failed to create event\n");
    return 1;
}

// Set event properties
event->kind = 1;  // Text note
event->created_at = time(NULL);
event->pubkey = pubkey;

// Set content
nostr_event_set_content(event, "Hello, Nostr!");

// Add tags (optional)
const char* e_tag[] = {"e", "some_event_id"};
nostr_event_add_tag(event, e_tag, 2);

// Compute event ID
nostr_event_compute_id(event);

// Sign the event
if (nostr_event_sign(event, &privkey) != NOSTR_OK) {
    fprintf(stderr, "Failed to sign event\n");
    nostr_event_destroy(event);
    return 1;
}

// Verify signature
if (nostr_event_verify(event) != NOSTR_OK) {
    fprintf(stderr, "Invalid event signature\n");
}

printf("Event created and signed successfully!\n");
```

### 4. Connect to a Relay

```c
nostr_relay* relay;

// Create relay connection
if (nostr_relay_create(&relay, "wss://relay.damus.io") != NOSTR_OK) {
    fprintf(stderr, "Failed to create relay\n");
    return 1;
}

// State change callback
void on_relay_state_change(nostr_relay* relay, nostr_relay_state state, void* user_data) {
    switch (state) {
        case NOSTR_RELAY_CONNECTED:
            printf("Connected to relay!\n");
            break;
        case NOSTR_RELAY_DISCONNECTED:
            printf("Disconnected from relay\n");
            break;
        case NOSTR_RELAY_ERROR:
            printf("Relay error\n");
            break;
        default:
            break;
    }
}

// Connect to relay
if (nostr_relay_connect(relay, on_relay_state_change, NULL) != NOSTR_OK) {
    fprintf(stderr, "Failed to connect to relay\n");
    nostr_relay_destroy(relay);
    return 1;
}
```

### 5. Publish an Event

```c
// Publish the event we created earlier
if (nostr_publish_event(relay, event) != NOSTR_OK) {
    fprintf(stderr, "Failed to publish event\n");
} else {
    printf("Event published successfully!\n");
}
```

### 6. Subscribe to Events

```c
// Event callback function
void on_event_received(const nostr_event* event, void* user_data) {
    printf("Received event: %s\n", event->content);
}

// Subscribe to text notes from specific authors
const char* filters = "{"
    "\"kinds\": [1],"
    "\"authors\": [\"your_pubkey_here\"],"
    "\"limit\": 10"
    "}";

if (nostr_subscribe(relay, "sub1", filters, on_event_received, NULL) != NOSTR_OK) {
    fprintf(stderr, "Failed to subscribe\n");
}
```

### 7. Working with Zaps

```c
// Create a zap request
nostr_event* zap_request;
const char* relays[] = {"wss://relay.damus.io", "wss://nostr.band"};

if (nostr_zap_create_request(&zap_request, 21000, &recipient_pubkey, 
                            "lnurl...", "Great post!", relays, 2) != NOSTR_OK) {
    fprintf(stderr, "Failed to create zap request\n");
    return 1;
}

// Sign the zap request
nostr_event_sign(zap_request, &sender_privkey);

// The zap request would then be sent to the LNURL endpoint
// (implementation depends on your Lightning integration)
```

## Complete Example

Here's a complete working example:

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <nostr.h>

void relay_callback(nostr_relay* relay, nostr_relay_state state, void* user_data) {
    switch (state) {
        case NOSTR_RELAY_CONNECTED:
            printf("Connected to relay\n");
            break;
        case NOSTR_RELAY_DISCONNECTED:
            printf("Disconnected from relay\n");
            break;
        case NOSTR_RELAY_ERROR:
            printf("Relay connection error\n");
            break;
        default:
            break;
    }
}

int main() {
    // Initialize library
    if (nostr_init() != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c\n");
        return 1;
    }

    // Generate keypair
    nostr_privkey privkey;
    nostr_key pubkey;
    if (nostr_key_generate(&privkey, &pubkey) != NOSTR_OK) {
        fprintf(stderr, "Failed to generate keypair\n");
        nostr_cleanup();
        return 1;
    }

    // Create event
    nostr_event* event;
    if (nostr_event_create(&event) != NOSTR_OK) {
        fprintf(stderr, "Failed to create event\n");
        nostr_cleanup();
        return 1;
    }

    event->kind = 1;
    event->created_at = time(NULL);
    event->pubkey = pubkey;
    nostr_event_set_content(event, "Hello from libnostr-c!");
    nostr_event_compute_id(event);
    nostr_event_sign(event, &privkey);

    // Connect to relay
    nostr_relay* relay;
    if (nostr_relay_create(&relay, "wss://relay.damus.io") != NOSTR_OK) {
        fprintf(stderr, "Failed to create relay\n");
        nostr_event_destroy(event);
        nostr_cleanup();
        return 1;
    }

    if (nostr_relay_connect(relay, relay_callback, NULL) != NOSTR_OK) {
        fprintf(stderr, "Failed to connect to relay\n");
        nostr_relay_destroy(relay);
        nostr_event_destroy(event);
        nostr_cleanup();
        return 1;
    }

    // Wait for connection
    sleep(2);

    // Publish event
    if (nostr_publish_event(relay, event) == NOSTR_OK) {
        printf("Event published successfully!\n");
    } else {
        printf("Failed to publish event\n");
    }

    // Clean up
    sleep(1);
    nostr_relay_disconnect(relay);
    nostr_relay_destroy(relay);
    nostr_event_destroy(event);
    nostr_cleanup();

    return 0;
}
```

## Next Steps

- Review the [API Reference](API.md) for detailed function documentation
- Check out [Examples](../examples/) for more complex use cases
- Read the [Integration Guide](INTEGRATION.md) for Bitcoin/Lightning projects
- See [Contributing Guidelines](CONTRIBUTING.md) to contribute to the project

## Troubleshooting

### Common Issues

1. **Compilation errors**: Ensure all dependencies are installed
2. **Connection failures**: Check firewall settings and relay availability
3. **Signature verification fails**: Verify key generation and event creation

### Getting Help

- **GitHub Issues**: [Report bugs or ask questions](https://github.com/privkeyio/libnostr-c/issues)
- **Documentation**: Check the docs/ directory for detailed guides
- **Examples**: Reference working code in the examples/ directory