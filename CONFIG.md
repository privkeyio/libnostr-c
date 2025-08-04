# Configuration Management

libnostr-c provides a comprehensive configuration system that allows runtime customization of library behavior through environment variables or programmatic configuration.

## Configuration Structure

The `nostr_config` structure contains the following configurable parameters:

### NIP-44 Encryption Limits
- `nip44_min_plaintext_size` (default: 1): Minimum plaintext size for NIP-44 encryption
- `nip44_max_plaintext_size` (default: 65535): Maximum plaintext size for NIP-44 encryption

### NIP-47 Wallet Connect Session Management
- `max_sessions` (default: 100): Maximum number of concurrent NIP-47 sessions
- `session_timeout_secs` (default: 3600): Session timeout in seconds (1 hour)
- `max_permissions` (default: 32): Maximum permissions per session

### Event Processing Limits
- `max_content_size` (default: 65536): Maximum event content size in bytes
- `max_tags` (default: 100): Maximum number of tags per event
- `max_tag_values` (default: 50): Maximum values per tag

### Network Configuration
- `relay_connect_timeout_ms` (default: 30000): Relay connection timeout in milliseconds
- `relay_response_timeout_ms` (default: 10000): Relay response timeout in milliseconds

### Security and Behavior Options
- `encryption_default_nip` (default: 44): Default encryption NIP (4 or 44)
- `secure_memory_lock` (default: 0): Enable mlock for sensitive data (0/1)
- `debug_mode` (default: 0): Enable debug logging (0/1)

## Environment Variables

All configuration options can be set via environment variables with the `NOSTR_` prefix:

```bash
export NOSTR_NIP44_MIN_SIZE=1
export NOSTR_NIP44_MAX_SIZE=65535
export NOSTR_MAX_SESSIONS=100
export NOSTR_SESSION_TIMEOUT=3600
export NOSTR_MAX_PERMISSIONS=32
export NOSTR_MAX_CONTENT_SIZE=65536
export NOSTR_MAX_TAGS=100
export NOSTR_MAX_TAG_VALUES=50
export NOSTR_RELAY_CONNECT_TIMEOUT=30000
export NOSTR_RELAY_RESPONSE_TIMEOUT=10000
export NOSTR_ENCRYPTION_DEFAULT=44
export NOSTR_SECURE_MEMORY_LOCK=0
export NOSTR_DEBUG=0
```

## Programmatic Configuration

### Basic Initialization
```c
// Initialize with defaults and environment variables
nostr_error_t err = nostr_init();

// Initialize with custom configuration
nostr_config config;
nostr_config_get_defaults(&config);
config.max_sessions = 200;
config.debug_mode = 1;
err = nostr_init_with_config(&config);
```

### Runtime Configuration Updates
```c
// Get current configuration
const nostr_config* current = nostr_config_get_current();

// Update configuration at runtime
nostr_config new_config = *current;
new_config.session_timeout_secs = 7200;
err = nostr_config_update(&new_config);
```

### Configuration Change Notifications
```c
void config_changed(const nostr_config* old_config, 
                   const nostr_config* new_config, 
                   void* user_data) {
    printf("Session timeout changed from %u to %u\n",
           old_config->session_timeout_secs,
           new_config->session_timeout_secs);
}

nostr_config_set_callback(config_changed, NULL);
```

## Validation Rules

All configuration values are validated with reasonable limits:

- NIP-44 sizes: 1-65535 bytes
- Sessions: 1-10000 concurrent sessions  
- Session timeout: 60-86400 seconds (1 minute to 1 day)
- Permissions: 1-1000 per session
- Content size: 1KB-1MB
- Tags: 1-1000 per event
- Tag values: 1-1000 per tag
- Timeouts: 1000-300000ms (1 second to 5 minutes)
- Encryption NIP: 4 or 44 only
- Boolean flags: 0 or 1

Invalid configurations are rejected with `NOSTR_ERR_INVALID_PARAM`.

## Performance Considerations

- Larger limits increase memory usage but provide more flexibility
- Shorter timeouts improve responsiveness but may cause premature disconnections
- Session limits prevent resource exhaustion but may limit concurrent users
- Debug mode impacts performance and should be disabled in production