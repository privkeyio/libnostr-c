/**
 * @file nostr.h
 * @brief libnostr-c: A C implementation of the Nostr protocol
 * 
 * This library provides a complete implementation of the Nostr protocol
 * including event creation, signing, verification, and relay communication.
 * 
 * @section thread_safety Thread Safety
 * 
 * This library is designed to be thread-safe with the following guarantees:
 * 
 * **Thread-Safe Functions (can be called concurrently):**
 * - All key generation, signing, and verification functions
 * - All encryption/decryption functions (NIP-04, NIP-44)
 * - All event creation and parsing functions 
 * - All utility functions (bech32, JSON, etc.)
 * - All NIP-specific functions (NIP-13, NIP-17, NIP-47, NIP-59)
 * 
 * **Initialization Functions (internally synchronized):**
 * - nostr_init() - safe to call from multiple threads
 * - nostr_init_with_config() - safe to call from multiple threads
 * - nostr_cleanup() - safe to call from multiple threads
 * - nostr_config_*() functions - internally synchronized
 * 
 * **Per-Object Thread Safety:**
 * - nostr_event, nostr_key, nostr_keypair: immutable after creation
 * - nostr_relay: not thread-safe, use separate instances per thread
 * - NIP-47 sessions: internally synchronized with per-session locks
 * 
 * **Best Practices:**
 * - Call nostr_init() once before using the library
 * - Use separate relay connections per thread
 * - Avoid sharing mutable objects between threads without external synchronization
 */

#ifndef NOSTR_H
#define NOSTR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "nostr_features.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Size of public keys in bytes */
#define NOSTR_PUBKEY_SIZE 32
/** @brief Size of private keys in bytes */
#define NOSTR_PRIVKEY_SIZE 32
/** @brief Size of signatures in bytes */
#define NOSTR_SIG_SIZE 64
/** @brief Size of event IDs in bytes */
#define NOSTR_ID_SIZE 32

/** @brief Standard Nostr HD derivation path (BIP-44 based) */
#define NOSTR_HD_PATH_STANDARD "m/44'/1237'/0'/0/0"
/** @brief Nostr coin type for BIP-44 (registered) */
#define NOSTR_COIN_TYPE 1237

/**
 * @brief Error codes returned by libnostr-c functions
 */
typedef enum {
    NOSTR_OK = 0,                    /**< Operation successful */
    NOSTR_ERR_INVALID_KEY,          /**< Invalid key format or data */
    NOSTR_ERR_INVALID_EVENT,        /**< Invalid event structure or data */
    NOSTR_ERR_INVALID_SIGNATURE,    /**< Invalid signature */
    NOSTR_ERR_MEMORY,               /**< Memory allocation failed */
    NOSTR_ERR_JSON_PARSE,           /**< JSON parsing error */
    NOSTR_ERR_ENCODING,             /**< Encoding/decoding error */
    NOSTR_ERR_CONNECTION,           /**< Connection error */
    NOSTR_ERR_PROTOCOL,             /**< Protocol error */
    NOSTR_ERR_NOT_FOUND,            /**< Resource not found */
    NOSTR_ERR_TIMEOUT,              /**< Operation timed out */
    NOSTR_ERR_INVALID_PARAM,        /**< Invalid parameter */
    NOSTR_ERR_NOT_SUPPORTED         /**< Feature not supported */
} nostr_error_t;

/**
 * @brief Configuration structure for library behavior
 */
typedef struct nostr_config {
    uint32_t nip44_min_plaintext_size;     /**< Minimum NIP-44 plaintext size */
    uint32_t nip44_max_plaintext_size;     /**< Maximum NIP-44 plaintext size */
    uint32_t max_sessions;                 /**< Maximum NIP-47 sessions */
    uint32_t session_timeout_secs;         /**< NIP-47 session timeout */
    uint32_t max_permissions;              /**< Maximum NIP-47 permissions */
    uint32_t max_content_size;             /**< Maximum event content size */
    uint32_t max_tags;                     /**< Maximum tags per event */
    uint32_t max_tag_values;               /**< Maximum values per tag */
    uint32_t relay_connect_timeout_ms;     /**< Relay connection timeout */
    uint32_t relay_response_timeout_ms;    /**< Relay response timeout */
    int encryption_default_nip;            /**< Default encryption (4 or 44) */
    int secure_memory_lock;                /**< Enable mlock for keys */
    int debug_mode;                        /**< Enable debug logging */
} nostr_config;

/**
 * @brief Public key structure
 */
typedef struct nostr_key {
    uint8_t data[NOSTR_PUBKEY_SIZE]; /**< Public key data */
} nostr_key;

/**
 * @brief Private key structure
 */
typedef struct nostr_privkey {
    uint8_t data[NOSTR_PRIVKEY_SIZE]; /**< Private key data */
} nostr_privkey;

/**
 * @brief Keypair structure combining public and private keys
 */
typedef struct nostr_keypair {
    nostr_privkey privkey;    /**< Private key */
    nostr_key pubkey;         /**< Public key */
    int initialized;          /**< Initialization flag */
} nostr_keypair;

/**
 * @brief Extended key structure for HD derivation (BIP-32)
 */
typedef struct nostr_extended_key {
    uint8_t version[4];           /**< Version bytes */
    uint8_t depth;                /**< Depth in derivation tree */
    uint8_t parent_fingerprint[4]; /**< Parent key fingerprint */
    uint32_t child_number;        /**< Child key index */
    uint8_t chain_code[32];       /**< Chain code */
    uint8_t key[33];              /**< Private (0x00 prefix) or public key */
} nostr_extended_key;

/**
 * @brief HD key derivation context
 */
typedef struct nostr_hd_key {
    nostr_privkey privkey;        /**< Private key */
    nostr_key pubkey;             /**< Public key */
    uint8_t chain_code[32];       /**< Chain code for derivation */
} nostr_hd_key;

/**
 * @brief Event tag structure
 */
typedef struct nostr_tag {
    char** values;  /**< Array of string values */
    size_t count;   /**< Number of values */
} nostr_tag;

/**
 * @brief Tag arena for efficient memory management
 */
typedef struct nostr_tag_arena {
    void* memory;     /**< Arena memory block */
    size_t capacity;  /**< Total arena capacity */
    size_t used;      /**< Used bytes */
} nostr_tag_arena;

/**
 * @brief Nostr event structure
 */
typedef struct nostr_event {
    uint8_t id[NOSTR_ID_SIZE];    /**< Event ID (SHA256 hash) */
    nostr_key pubkey;             /**< Author's public key */
    int64_t created_at;           /**< Unix timestamp */
    uint16_t kind;                /**< Event kind */
    nostr_tag* tags;              /**< Array of tags */
    size_t tags_count;            /**< Number of tags */
    char* content;                /**< Event content */
    uint8_t sig[NOSTR_SIG_SIZE];  /**< Event signature */
    nostr_tag_arena* tag_arena;   /**< Tag memory arena */
} nostr_event;

/**
 * @brief Relay connection states
 */
typedef enum {
    NOSTR_RELAY_DISCONNECTED = 0,  /**< Relay is disconnected */
    NOSTR_RELAY_CONNECTING,        /**< Relay is connecting */
    NOSTR_RELAY_CONNECTED,         /**< Relay is connected */
    NOSTR_RELAY_ERROR             /**< Relay error state */
} nostr_relay_state;

/**
 * @brief Callback function for relay notifications
 * @param message_type Type of message (OK, EOSE, NOTICE, etc.)
 * @param data Message data in JSON format
 * @param user_data User-defined data
 */
typedef void (*nostr_message_callback)(const char* message_type, const char* data, void* user_data);

/**
 * @brief Relay connection structure
 */
typedef struct nostr_relay {
    char* url;                    /**< Relay WebSocket URL */
    nostr_relay_state state;      /**< Current connection state */
    void* ws_handle;              /**< WebSocket handle (opaque) */
    void* user_data;              /**< User-defined data */
    nostr_message_callback message_callback; /**< Message callback */
    void* message_user_data;      /**< Message callback user data */
} nostr_relay;

/**
 * @brief Callback function for received events
 * @param event The received event
 * @param user_data User-defined data
 */
typedef void (*nostr_event_callback)(const nostr_event* event, void* user_data);

/**
 * @brief Callback function for relay state changes
 * @param relay The relay instance
 * @param state New relay state
 * @param user_data User-defined data
 */
typedef void (*nostr_relay_callback)(struct nostr_relay* relay, nostr_relay_state state, void* user_data);

/**
 * @brief Initialize the libnostr-c library
 * @return NOSTR_OK on success, error code otherwise
 * @note Thread-safe: Yes (internally synchronized)
 */
nostr_error_t nostr_init(void);

/**
 * @brief Initialize the libnostr-c library with configuration
 * @param config Configuration structure (NULL for defaults)
 * @return NOSTR_OK on success, error code otherwise
 * @note Thread-safe: Yes (internally synchronized)
 */
nostr_error_t nostr_init_with_config(const nostr_config* config);

/**
 * @brief Get default configuration
 * @param config Output configuration structure
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_config_get_defaults(nostr_config* config);

/**
 * @brief Load configuration from environment variables
 * @param config Configuration structure to update
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_config_load_env(nostr_config* config);

/**
 * @brief Validate configuration values
 * @param config Configuration to validate
 * @return NOSTR_OK if valid, error code otherwise
 */
nostr_error_t nostr_config_validate(const nostr_config* config);

/**
 * @brief Get current active configuration
 * @param config Output current configuration (NULL returns pointer to internal)
 * @return Pointer to current config, or NULL if not initialized
 */
const nostr_config* nostr_config_get_current(void);

/**
 * @brief Configuration change notification callback
 * @param old_config Previous configuration
 * @param new_config New configuration
 * @param user_data User-defined data
 */
typedef void (*nostr_config_callback)(const nostr_config* old_config, const nostr_config* new_config, void* user_data);

/**
 * @brief Set configuration change callback
 * @param callback Callback function
 * @param user_data User data for callback
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_config_set_callback(nostr_config_callback callback, void* user_data);

/**
 * @brief Update runtime configuration
 * @param config New configuration to apply
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_config_update(const nostr_config* config);

/**
 * @brief Clean up the libnostr-c library
 */
void nostr_cleanup(void);

/**
 * @brief Generate a new keypair
 * @param privkey Output private key
 * @param pubkey Output public key
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_key_generate(nostr_privkey* privkey, nostr_key* pubkey);

/**
 * @brief Initialize a keypair structure
 * @param keypair Keypair to initialize
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_keypair_init(nostr_keypair* keypair);

/**
 * @brief Generate a new keypair using the keypair structure
 * @param keypair Output keypair
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_keypair_generate(nostr_keypair* keypair);

/**
 * @brief Import keypair from private key hex string
 * @param keypair Output keypair
 * @param privkey_hex Private key hex string (64 characters)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_keypair_from_private_hex(nostr_keypair* keypair, const char* privkey_hex);

/**
 * @brief Import keypair from private key
 * @param keypair Output keypair
 * @param privkey Private key to import
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_keypair_from_private_key(nostr_keypair* keypair, const nostr_privkey* privkey);

/**
 * @brief Export private key from keypair to hex string
 * @param keypair Input keypair
 * @param hex Output hex string buffer
 * @param hex_size Size of hex buffer (must be at least 65)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_keypair_export_private_hex(const nostr_keypair* keypair, char* hex, size_t hex_size);

/**
 * @brief Export public key from keypair to hex string
 * @param keypair Input keypair
 * @param hex Output hex string buffer
 * @param hex_size Size of hex buffer (must be at least 65)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_keypair_export_public_hex(const nostr_keypair* keypair, char* hex, size_t hex_size);

/**
 * @brief Validate a keypair
 * @param keypair Keypair to validate
 * @return NOSTR_OK if valid, error code otherwise
 */
nostr_error_t nostr_keypair_validate(const nostr_keypair* keypair);

/**
 * @brief Get public key pointer from keypair
 * @param keypair Input keypair
 * @return Pointer to public key, NULL if invalid
 */
const nostr_key* nostr_keypair_public_key(const nostr_keypair* keypair);

/**
 * @brief Get private key pointer from keypair
 * @param keypair Input keypair
 * @return Pointer to private key, NULL if invalid
 */
const nostr_privkey* nostr_keypair_private_key(const nostr_keypair* keypair);

/**
 * @brief Securely destroy a keypair
 * @param keypair Keypair to destroy
 */
void nostr_keypair_destroy(nostr_keypair* keypair);

/**
 * @brief Convert hex string to public key
 * @param hex Input hex string (64 characters)
 * @param key Output public key
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_key_from_hex(const char* hex, nostr_key* key);

/**
 * @brief Convert public key to hex string
 * @param key Input public key
 * @param hex Output hex string buffer
 * @param hex_size Size of hex buffer (must be at least 65)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_key_to_hex(const nostr_key* key, char* hex, size_t hex_size);

/**
 * @brief Convert hex string to private key
 * @param hex Input hex string (64 characters)
 * @param privkey Output private key
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_privkey_from_hex(const char* hex, nostr_privkey* privkey);

/**
 * @brief Convert private key to hex string
 * @param privkey Input private key
 * @param hex Output hex string buffer
 * @param hex_size Size of hex buffer (must be at least 65)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_privkey_to_hex(const nostr_privkey* privkey, char* hex, size_t hex_size);

/**
 * @brief Perform ECDH to generate shared secret
 * @param privkey Private key
 * @param pubkey Public key
 * @param shared_secret Output shared secret (32 bytes, x-coordinate only)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_key_ecdh(const nostr_privkey* privkey, const nostr_key* pubkey, uint8_t shared_secret[32]);

/**
 * @brief Generate HD master key from seed (BIP-32)
 * @param seed Seed bytes
 * @param seed_len Length of seed (128-512 bits recommended)
 * @param master Output HD master key
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_hd_key_from_seed(const uint8_t* seed, size_t seed_len, nostr_hd_key* master);

/**
 * @brief Derive child HD key
 * @param parent Parent HD key
 * @param index Child key index (>=0x80000000 for hardened derivation)
 * @param child Output child HD key
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_hd_key_derive(const nostr_hd_key* parent, uint32_t index, nostr_hd_key* child);

/**
 * @brief Derive HD key from path (e.g., "m/44'/1237'/0'/0/0")
 * @param master Master HD key
 * @param path Derivation path string
 * @param derived Output derived HD key
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_hd_key_derive_path(const nostr_hd_key* master, const char* path, nostr_hd_key* derived);

/**
 * @brief Export HD key to nostr_keypair
 * @param hd_key Input HD key
 * @param keypair Output keypair
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_hd_key_to_keypair(const nostr_hd_key* hd_key, nostr_keypair* keypair);

/**
 * @brief Generate a BIP39 mnemonic phrase (NIP-06)
 * @param word_count Number of words (12 or 24)
 * @param mnemonic Output buffer for mnemonic phrase
 * @param mnemonic_size Size of output buffer
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_mnemonic_generate(int word_count, char* mnemonic, size_t mnemonic_size);

/**
 * @brief Validate a BIP39 mnemonic phrase checksum (NIP-06)
 * @param mnemonic Mnemonic phrase to validate
 * @return NOSTR_OK if valid, NOSTR_ERR_INVALID_PARAM if invalid
 */
nostr_error_t nostr_mnemonic_validate(const char* mnemonic);

/**
 * @brief Derive seed from BIP39 mnemonic (NIP-06)
 * @param mnemonic Mnemonic phrase
 * @param passphrase Optional passphrase (NULL for none)
 * @param seed Output 64-byte seed buffer
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_mnemonic_to_seed(const char* mnemonic, const char* passphrase, uint8_t seed[64]);

/**
 * @brief Derive Nostr keypair from mnemonic using NIP-06 path
 * @param mnemonic Mnemonic phrase
 * @param passphrase Optional passphrase (NULL for none)
 * @param account Account index (typically 0)
 * @param keypair Output keypair
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_mnemonic_to_keypair(const char* mnemonic, const char* passphrase,
                                        uint32_t account, nostr_keypair* keypair);

/**
 * @brief Convert public key to bech32 format
 * @param key Input public key
 * @param prefix Bech32 prefix (e.g., "npub")
 * @param bech32 Output bech32 string buffer
 * @param bech32_size Size of bech32 buffer
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_key_to_bech32(const nostr_key* key, const char* prefix, char* bech32, size_t bech32_size);

/**
 * @brief Convert bech32 string to public key
 * @param bech32 Input bech32 string
 * @param key Output public key
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_key_from_bech32(const char* bech32, nostr_key* key);

/**
 * @brief Convert private key to bech32 format (nsec)
 * @param privkey Input private key
 * @param bech32 Output bech32 string buffer
 * @param bech32_size Size of bech32 buffer
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_privkey_to_bech32(const nostr_privkey* privkey, char* bech32, size_t bech32_size);

/**
 * @brief Convert bech32 string to private key
 * @param bech32 Input bech32 string (nsec)
 * @param privkey Output private key
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_privkey_from_bech32(const char* bech32, nostr_privkey* privkey);

/**
 * @brief Convert event ID to bech32 format (note)
 * @param id Input event ID (32 bytes)
 * @param bech32 Output bech32 string buffer
 * @param bech32_size Size of bech32 buffer
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_id_to_bech32(const uint8_t* id, char* bech32, size_t bech32_size);

/**
 * @brief Convert bech32 string to event ID
 * @param bech32 Input bech32 string (note)
 * @param id Output event ID buffer (32 bytes)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_id_from_bech32(const char* bech32, uint8_t* id);

/**
 * @brief Create a new event
 * @param event Output event pointer
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_create(nostr_event** event);

/**
 * @brief Destroy an event and free its memory
 * @param event Event to destroy
 */
void nostr_event_destroy(nostr_event* event);

/**
 * @brief Set event content
 * @param event Event to modify
 * @param content Content string
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_set_content(nostr_event* event, const char* content);

/**
 * @brief Add a tag to an event
 * @param event Event to modify
 * @param values Array of tag values
 * @param count Number of values
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_add_tag(nostr_event* event, const char** values, size_t count);

/**
 * @brief Compute event ID (SHA256 hash)
 * @param event Event to compute ID for
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_compute_id(nostr_event* event);

/**
 * @brief Sign an event
 * @param event Event to sign
 * @param privkey Private key for signing
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_sign(nostr_event* event, const nostr_privkey* privkey);

/**
 * @brief Verify event signature
 * @param event Event to verify
 * @return NOSTR_OK if valid, NOSTR_ERR_INVALID_SIGNATURE otherwise
 */
nostr_error_t nostr_event_verify(const nostr_event* event);

/**
 * @brief Serialize event to JSON
 * @param event Event to serialize
 * @param json Output JSON string (caller must free)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_to_json(const nostr_event* event, char** json);

/**
 * @brief Parse event from JSON
 * @param json Input JSON string
 * @param event Output event pointer
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_from_json(const char* json, nostr_event** event);

/**
 * @brief Create a new relay connection
 * @param relay Output relay pointer
 * @param url WebSocket URL (e.g., "wss://relay.damus.io")
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_relay_create(nostr_relay** relay, const char* url);

/**
 * @brief Destroy a relay connection
 * @param relay Relay to destroy
 */
void nostr_relay_destroy(nostr_relay* relay);

/**
 * @brief Connect to a relay
 * @param relay Relay instance
 * @param callback State change callback
 * @param user_data User data for callback
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_relay_connect(nostr_relay* relay, nostr_relay_callback callback, void* user_data);

/**
 * @brief Disconnect from a relay
 * @param relay Relay instance
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_relay_disconnect(nostr_relay* relay);

/**
 * @brief Send an event to a relay
 * @param relay Relay instance
 * @param event Event to send
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_relay_send_event(nostr_relay* relay, const nostr_event* event);

/**
 * @brief Subscribe to events matching filters
 * @param relay Relay instance
 * @param subscription_id Unique subscription ID
 * @param filters_json JSON filters (NIP-01 format)
 * @param callback Event callback
 * @param user_data User data for callback
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_subscribe(nostr_relay* relay, const char* subscription_id, const char* filters_json, nostr_event_callback callback, void* user_data);

/**
 * @brief Publish an event to a relay
 * @param relay Relay instance
 * @param event Event to publish
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_publish_event(nostr_relay* relay, const nostr_event* event);

/**
 * @brief Unsubscribe from a subscription
 * @param relay Relay instance
 * @param subscription_id Subscription ID to cancel
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_relay_unsubscribe(nostr_relay* relay, const char* subscription_id);

/**
 * @brief Set the message callback for relay notifications
 * @param relay Relay instance
 * @param callback Message callback function
 * @param user_data User data for callback
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_relay_set_message_callback(nostr_relay* relay, nostr_message_callback callback, void* user_data);

/**
 * @brief Get human-readable error string
 * @param error Error code
 * @return Error message string
 */
const char* nostr_error_string(nostr_error_t error);

/**
 * @brief Constant-time memory comparison
 * @param a First memory buffer
 * @param b Second memory buffer
 * @param n Number of bytes to compare
 * @return 0 if equal, non-zero if different
 */
int nostr_constant_time_memcmp(const void* a, const void* b, size_t n);

/**
 * @brief Securely wipe memory to prevent data recovery
 * @param ptr Pointer to memory buffer
 * @param len Number of bytes to wipe
 */
void secure_wipe(void* ptr, size_t len);

/**
 * @brief Decode hex string to bytes
 * @param hex Input hex string
 * @param out Output byte buffer
 * @param out_len Size of output buffer
 * @return Number of bytes written, or -1 on error
 */
int nostr_hex_decode(const char* hex, uint8_t* out, size_t out_len);

/**
 * @brief Encode bytes to hex string
 * @param bytes Input byte buffer
 * @param len Number of bytes to encode
 * @param out Output hex string buffer (must be at least len*2+1)
 */
void nostr_hex_encode(const uint8_t* bytes, size_t len, char* out);

/**
 * @brief Fill buffer with cryptographically secure random bytes
 * @param buf Output buffer
 * @param len Number of bytes to generate
 * @return 1 on success, 0 on error
 */
int nostr_random_bytes(uint8_t* buf, size_t len);

/**
 * @brief Create a zap request event (NIP-57 kind 9734)
 * @param event Output event pointer
 * @param amount Amount in millisats
 * @param recipient Recipient's public key
 * @param lnurl Recipient's LNURL
 * @param content Optional zap message/comment
 * @param relays Array of relay URLs to publish zap receipt to
 * @param relays_count Number of relays
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_zap_create_request(nostr_event** event, uint64_t amount, const nostr_key* recipient, const char* lnurl, const char* content, const char** relays, size_t relays_count);

/**
 * @brief Validate an LNURL for zap support
 * @param lnurl LNURL to validate
 * @param nostr_pubkey Output buffer for server's nostr pubkey (optional, 33 bytes)
 * @param allows_nostr Output flag indicating if server supports nostr zaps (optional)
 * @return NOSTR_OK if valid, error code otherwise
 */
nostr_error_t nostr_zap_validate_lnurl(const char* lnurl, char* nostr_pubkey, bool* allows_nostr);

/**
 * @brief Parse zap receipt event (NIP-57 kind 9735)
 * @param event Input zap receipt event
 * @param amount Output amount in millisats (optional)
 * @param bolt11 Output bolt11 invoice (optional, caller must free)
 * @param preimage Output preimage (optional, 64 bytes hex)
 * @param zap_request Output zap request event (optional, caller must free)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_zap_parse_receipt(const nostr_event* event, uint64_t* amount, char** bolt11, char* preimage, nostr_event** zap_request);

/**
 * @brief Verify a zap receipt against the original request
 * @param receipt Zap receipt event (kind 9735)
 * @param request Original zap request event (kind 9734)
 * @param server_pubkey Expected server's nostr pubkey
 * @return NOSTR_OK if valid, error code otherwise
 */
nostr_error_t nostr_zap_verify(const nostr_event* receipt, const nostr_event* request, const char* server_pubkey);

/**
 * @brief Encrypt a message using NIP-44 encryption
 * @param sender_privkey Sender's private key
 * @param recipient_pubkey Recipient's public key
 * @param plaintext Message to encrypt
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output encrypted message (caller must free)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip44_encrypt(const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey, 
                                  const char* plaintext, size_t plaintext_len, char** ciphertext);

/**
 * @brief Encrypt a message using NIP-04 legacy encryption (DEPRECATED)
 * @deprecated Use nostr_nip44_encrypt() instead for better security
 * @param sender_privkey Sender's private key
 * @param recipient_pubkey Recipient's public key
 * @param plaintext Message to encrypt
 * @param ciphertext Output encrypted message (caller must free)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip04_encrypt(const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey, 
                                  const char* plaintext, char** ciphertext);

/**
 * @brief Decrypt a message using NIP-44 encryption
 * @param recipient_privkey Recipient's private key
 * @param sender_pubkey Sender's public key
 * @param ciphertext Encrypted message
 * @param plaintext Output decrypted message (caller must free)
 * @param plaintext_len Output length of decrypted message
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip44_decrypt(const nostr_privkey* recipient_privkey, const nostr_key* sender_pubkey,
                                  const char* ciphertext, char** plaintext, size_t* plaintext_len);

/**
 * @brief Decrypt a message using NIP-04 legacy encryption (DEPRECATED)
 * @deprecated Use nostr_nip44_decrypt() instead for better security
 * @param recipient_privkey Recipient's private key
 * @param sender_pubkey Sender's public key
 * @param ciphertext Encrypted message in format "content?iv=base64"
 * @param plaintext Output decrypted message (caller must free)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip04_decrypt(const nostr_privkey* recipient_privkey, const nostr_key* sender_pubkey,
                                  const char* ciphertext, char** plaintext);

/**
 * @brief Create a rumor (unsigned event) for NIP-17
 * @param rumor Output rumor event pointer
 * @param kind Event kind
 * @param pubkey Author's public key
 * @param content Event content
 * @param created_at Optional timestamp (0 for current time)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip17_create_rumor(nostr_event** rumor, uint16_t kind, const nostr_key* pubkey, 
                                       const char* content, int64_t created_at);

/**
 * @brief Create a seal event (kind 13) for NIP-17
 * @param seal Output seal event pointer
 * @param rumor Input rumor event to seal
 * @param sender_privkey Sender's private key
 * @param recipient_pubkey Recipient's public key
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip17_create_seal(nostr_event** seal, const nostr_event* rumor,
                                      const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey);

/**
 * @brief Create a gift wrap event (kind 1059) for NIP-17
 * @param wrap Output gift wrap event pointer
 * @param seal Input seal event to wrap
 * @param recipient_pubkey Recipient's public key
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip17_create_gift_wrap(nostr_event** wrap, const nostr_event* seal,
                                           const nostr_key* recipient_pubkey);

/**
 * @brief Send a private direct message using NIP-17
 * @param dm Output gift wrap event pointer (for sender's copy)
 * @param content Message content
 * @param sender_privkey Sender's private key
 * @param recipient_pubkey Recipient's public key
 * @param subject Optional conversation subject/title
 * @param reply_to Optional event ID being replied to
 * @param created_at Optional timestamp (0 for current time)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip17_send_dm(nostr_event** dm, const char* content,
                                  const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey,
                                  const char* subject, const uint8_t* reply_to, int64_t created_at);

/**
 * @brief Unwrap and decrypt a received NIP-17 gift wrap
 * @param wrap Input gift wrap event
 * @param recipient_privkey Recipient's private key
 * @param rumor Output decrypted rumor event (caller must destroy)
 * @param sender_pubkey Output sender's public key (from seal)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip17_unwrap_dm(const nostr_event* wrap, const nostr_privkey* recipient_privkey,
                                    nostr_event** rumor, nostr_key* sender_pubkey);

/**
 * @brief Wrap any event using NIP-59 gift wrap protocol
 * @param gift_wrap Output gift wrap event pointer
 * @param event_to_wrap Input event to wrap (can be any kind)
 * @param author_privkey Author's private key (for sealing)
 * @param recipient_pubkey Recipient's public key
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip59_wrap_event(nostr_event** gift_wrap, const nostr_event* event_to_wrap,
                                     const nostr_privkey* author_privkey, const nostr_key* recipient_pubkey);

/**
 * @brief Unwrap a NIP-59 gift wrap event
 * @param gift_wrap Input gift wrap event (kind 1059)
 * @param recipient_privkey Recipient's private key
 * @param unwrapped_event Output unwrapped event (caller must destroy)
 * @param author_pubkey Output author's public key from seal (optional)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip59_unwrap_event(const nostr_event* gift_wrap, const nostr_privkey* recipient_privkey,
                                       nostr_event** unwrapped_event, nostr_key* author_pubkey);

/**
 * @brief Create a rumor (unsigned event) for NIP-59
 * @param rumor Output rumor event pointer
 * @param kind Event kind
 * @param pubkey Author's public key
 * @param content Event content (optional)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip59_create_rumor(nostr_event** rumor, uint16_t kind, const nostr_key* pubkey,
                                       const char* content);

/**
 * @brief Create a seal event (kind 13) for NIP-59
 * @param seal Output seal event pointer
 * @param rumor Input rumor event to seal
 * @param author_privkey Author's private key
 * @param recipient_pubkey Recipient's public key
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip59_create_seal(nostr_event** seal, const nostr_event* rumor,
                                      const nostr_privkey* author_privkey, const nostr_key* recipient_pubkey);

/**
 * @brief Create a gift wrap event (kind 1059) for NIP-59
 * @param gift_wrap Output gift wrap event pointer
 * @param seal Input seal event to wrap
 * @param recipient_pubkey Recipient's public key
 * @param extra_tags Optional additional tags (key-value pairs)
 * @param tags_count Number of extra tag elements (must be even)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip59_create_gift_wrap(nostr_event** gift_wrap, const nostr_event* seal,
                                           const nostr_key* recipient_pubkey, const char** extra_tags, size_t tags_count);

// NIP-46 Nostr Connect (Remote Signer) types and functions
#define NOSTR_NIP46_KIND 24133

typedef struct nostr_nip46_request {
    char id[65];
    char method[32];
    char* params;
    size_t params_len;
    nostr_key sender_pubkey;
} nostr_nip46_request_t;

typedef struct nostr_nip46_response {
    char id[65];
    char* result;
    char* error;
} nostr_nip46_response_t;

nostr_error_t nostr_nip46_parse_request(const nostr_event* event,
                                        const nostr_privkey* recipient_privkey,
                                        nostr_nip46_request_t* request);

nostr_error_t nostr_nip46_create_response(const nostr_nip46_response_t* response,
                                          const nostr_privkey* signer_privkey,
                                          const nostr_key* recipient_pubkey,
                                          nostr_event** event_out);

void nostr_nip46_request_free(nostr_nip46_request_t* request);
void nostr_nip46_response_free(nostr_nip46_response_t* response);

// NIP-47 Nostr Wallet Connect functions
typedef struct nwc_connection nwc_connection_t;

nostr_error_t nostr_nip47_parse_connection_uri(const char* uri, struct nwc_connection** connection);
nostr_error_t nostr_nip47_free_connection(struct nwc_connection* connection);

nostr_error_t nostr_nip47_parse_info_event(const nostr_event* event, char*** capabilities, 
                                           size_t* cap_count, char*** notifications, 
                                           size_t* notif_count, char*** encryptions,
                                           size_t* enc_count);

nostr_error_t nostr_nip47_create_request_event(nostr_event** event, const struct nwc_connection* conn,
                                               const char* method, const char* params_json,
                                               int use_nip44);

nostr_error_t nostr_nip47_parse_response_event(const nostr_event* event, const nostr_privkey* client_secret,
                                               char** result_type, char** result_json, 
                                               char** error_code, char** error_message);

nostr_error_t nostr_nip47_parse_notification_event(const nostr_event* event, const nostr_privkey* client_secret,
                                                   char** notification_type, char** notification_json);

// Helper functions for creating common request parameters
nostr_error_t nostr_nip47_create_pay_invoice_params(char** params_json, const char* invoice, 
                                                    uint64_t* amount_msats);
nostr_error_t nostr_nip47_create_get_balance_params(char** params_json);
nostr_error_t nostr_nip47_create_make_invoice_params(char** params_json, uint64_t amount_msats,
                                                     const char* description, const char* description_hash,
                                                     uint32_t* expiry_secs);
nostr_error_t nostr_nip47_create_list_transactions_params(char** params_json, time_t* from, time_t* until,
                                                         uint32_t* limit, uint32_t* offset, 
                                                         int* unpaid, const char* type);
nostr_error_t nostr_nip47_create_lookup_invoice_params(char** params_json, const char* payment_hash,
                                                       const char* invoice);
nostr_error_t nostr_nip47_create_pay_keysend_params(char** params_json, uint64_t amount_msats,
                                                    const char* pubkey, const char* preimage,
                                                    const char** tlv_records, size_t tlv_count);
nostr_error_t nostr_nip47_create_multi_pay_invoice_params(char** params_json, 
                                                          const char** invoice_ids,
                                                          const char** invoices,
                                                          uint64_t* amounts, 
                                                          size_t count);
nostr_error_t nostr_nip47_create_get_info_params(char** params_json);

// Helper functions for parsing responses
nostr_error_t nostr_nip47_parse_balance_response(const char* result_json, uint64_t* balance_msats);
nostr_error_t nostr_nip47_parse_pay_invoice_response(const char* result_json, char** preimage,
                                                     uint64_t* fees_paid);
nostr_error_t nostr_nip47_parse_info_response(const char* result_json, char** alias, char** color,
                                              char** pubkey, char** network, uint32_t* block_height,
                                              char*** methods, size_t* method_count);

// Session management for NIP-47
nostr_error_t nostr_nip47_session_init(void);
nostr_error_t nostr_nip47_session_create(const char* connection_uri, char** session_id);
nostr_error_t nostr_nip47_session_add_permission(const char* session_id, const char* permission,
                                                 uint64_t limit_msats, uint32_t reset_interval_secs);
nostr_error_t nostr_nip47_session_check_permission(const char* session_id, const char* method,
                                                   uint64_t amount_msats);
nostr_error_t nostr_nip47_session_get_connection(const char* session_id, struct nwc_connection** connection);
nostr_error_t nostr_nip47_session_extend(const char* session_id, uint32_t additional_secs);
nostr_error_t nostr_nip47_session_destroy(const char* session_id);

/**
 * @brief Calculate difficulty (leading zero bits) from event ID
 * @param event_id Event ID (32 bytes)
 * @return Number of leading zero bits
 */
int nostr_nip13_calculate_difficulty(const uint8_t* event_id);

/**
 * @brief Mine an event to achieve target difficulty
 * @param event Event to mine (must have nonce tag)
 * @param target_difficulty Target number of leading zero bits
 * @param max_iterations Maximum mining iterations (0 for unlimited)
 * @return NOSTR_OK on success, NOSTR_ERR_NOT_FOUND if target not reached
 */
nostr_error_t nostr_nip13_mine_event(nostr_event* event, int target_difficulty, uint64_t max_iterations);

/**
 * @brief Verify proof of work for an event
 * @param event Event to verify
 * @param min_difficulty Minimum required difficulty
 * @return NOSTR_OK if valid, error code otherwise
 */
nostr_error_t nostr_nip13_verify_pow(const nostr_event* event, int min_difficulty);

/**
 * @brief Add or update nonce tag for mining
 * @param event Event to modify
 * @param nonce_value Initial nonce value
 * @param target_difficulty Target difficulty (optional, 0 to omit)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_nip13_add_nonce_tag(nostr_event* event, uint64_t nonce_value, int target_difficulty);

/**
 * @brief Mine an event using multiple threads
 * @param event Event to mine (must have nonce tag)
 * @param target_difficulty Target number of leading zero bits
 * @param num_threads Number of threads to use (0 for auto-detect)
 * @param max_iterations Maximum mining iterations per thread (0 for unlimited)
 * @return NOSTR_OK on success, NOSTR_ERR_NOT_FOUND if target not reached
 */
nostr_error_t nostr_nip13_mine_event_threaded(nostr_event* event, int target_difficulty, int num_threads, uint64_t max_iterations);

/**
 * @brief Get the root event ID from a threaded event (NIP-10)
 * @param event Event to extract root from
 * @param root_id Output buffer for root event ID (at least 65 bytes)
 * @param root_id_size Size of root_id buffer
 * @param relay_hint Output buffer for relay hint (optional, can be NULL)
 * @param relay_hint_size Size of relay_hint buffer
 * @return NOSTR_OK on success, NOSTR_ERR_NOT_FOUND if no root found
 */
nostr_error_t nostr_event_get_root_id(const nostr_event* event, char* root_id, size_t root_id_size,
                                      char* relay_hint, size_t relay_hint_size);

/**
 * @brief Get the direct reply event ID from a threaded event (NIP-10)
 * @param event Event to extract reply from
 * @param reply_id Output buffer for reply event ID (at least 65 bytes)
 * @param reply_id_size Size of reply_id buffer
 * @param relay_hint Output buffer for relay hint (optional, can be NULL)
 * @param relay_hint_size Size of relay_hint buffer
 * @return NOSTR_OK on success, NOSTR_ERR_NOT_FOUND if no reply found
 */
nostr_error_t nostr_event_get_reply_id(const nostr_event* event, char* reply_id, size_t reply_id_size,
                                       char* relay_hint, size_t relay_hint_size);

/**
 * @brief Add threading tags to an event (NIP-10)
 * @param event Event to add tags to
 * @param root_id Root event ID (NULL if replying to root directly)
 * @param root_relay Relay hint for root event (optional)
 * @param root_pubkey Author pubkey of root event (optional)
 * @param reply_id Reply event ID (NULL if this is a direct reply to root)
 * @param reply_relay Relay hint for reply event (optional)
 * @param reply_pubkey Author pubkey of reply event (optional)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_add_reply_tags(nostr_event* event, const char* root_id, const char* root_relay,
                                         const char* root_pubkey, const char* reply_id,
                                         const char* reply_relay, const char* reply_pubkey);

/**
 * @brief Add a mention p-tag to an event (NIP-10)
 * @param event Event to add mention to
 * @param pubkey Pubkey to mention
 * @param relay_hint Relay hint for the mentioned pubkey (optional)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_add_mention_tag(nostr_event* event, const char* pubkey, const char* relay_hint);

/**
 * @brief Check if an event is a reply to another event (NIP-10)
 * @param event Event to check
 * @param is_reply Output: 1 if event is a reply, 0 otherwise
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_is_reply(const nostr_event* event, int* is_reply);

/**
 * @brief Create a reaction event (NIP-25)
 * @param event Output event pointer
 * @param reaction_content Reaction content ("+", "-", or emoji; NULL defaults to "+")
 * @param target_event_id ID of event being reacted to
 * @param target_pubkey Pubkey of event author being reacted to
 * @param relay_hint Relay hint for target event (optional)
 * @param target_kind Kind of target event (0 to omit k tag)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_reaction_create(nostr_event** event, const char* reaction_content,
                                    const char* target_event_id, const char* target_pubkey,
                                    const char* relay_hint, uint16_t target_kind);

/**
 * @brief Parse a reaction event (NIP-25)
 * @param event Input reaction event (must be kind 7)
 * @param reaction_content Output buffer for reaction content (optional)
 * @param content_size Size of reaction_content buffer
 * @param target_event_id Output buffer for target event ID (optional)
 * @param event_id_size Size of target_event_id buffer
 * @param target_pubkey Output buffer for target pubkey (optional)
 * @param pubkey_size Size of target_pubkey buffer
 * @param target_kind Output for target event kind (optional)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_reaction_parse(const nostr_event* event, char* reaction_content, size_t content_size,
                                   char* target_event_id, size_t event_id_size,
                                   char* target_pubkey, size_t pubkey_size,
                                   uint16_t* target_kind);

/**
 * @brief Check if a reaction event is a like/upvote (NIP-25)
 * @param event Reaction event to check
 * @param is_like Output: 1 if reaction is a like, 0 otherwise
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_reaction_is_like(const nostr_event* event, int* is_like);

/**
 * @brief Check if a reaction event is a dislike/downvote (NIP-25)
 * @param event Reaction event to check
 * @param is_dislike Output: 1 if reaction is a dislike, 0 otherwise
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_reaction_is_dislike(const nostr_event* event, int* is_dislike);

/**
 * @brief Create a repost event (NIP-18)
 * @param event Output event pointer
 * @param reposted_event_id ID of event being reposted (64-char hex)
 * @param reposted_pubkey Pubkey of original event author (64-char hex)
 * @param relay_hint Relay URL where original event can be found (required)
 * @param reposted_kind Kind of reposted event (1 for kind:6, other for kind:16)
 * @param d_tag Optional d-tag for replaceable events (adds "a" tag with kind:pubkey:d-tag)
 * @param embedded_json Optional stringified JSON of reposted event (can be NULL)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_repost_create(nostr_event** event, const char* reposted_event_id,
                                  const char* reposted_pubkey, const char* relay_hint,
                                  uint16_t reposted_kind, const char* d_tag,
                                  const char* embedded_json);

/**
 * @brief Parse a repost event (NIP-18)
 * @param event Input repost event (must be kind 6 or 16)
 * @param reposted_event_id Output buffer for reposted event ID (optional, at least 65 bytes)
 * @param event_id_size Size of reposted_event_id buffer
 * @param reposted_pubkey Output buffer for reposted pubkey (optional, at least 65 bytes)
 * @param pubkey_size Size of reposted_pubkey buffer
 * @param relay_hint Output buffer for relay hint (optional)
 * @param relay_hint_size Size of relay_hint buffer
 * @param reposted_kind Output for reposted event kind (optional, from k tag)
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_repost_parse(const nostr_event* event, char* reposted_event_id, size_t event_id_size,
                                 char* reposted_pubkey, size_t pubkey_size,
                                 char* relay_hint, size_t relay_hint_size,
                                 uint16_t* reposted_kind);

/**
 * @brief Extract quote tags from event content (NIP-18)
 *
 * Scans the event content for nostr: URI mentions (note1..., nevent1..., naddr1...)
 * and adds corresponding q tags to the event. This ensures quote reposts are not
 * pulled and included as replies in threads.
 *
 * @param event Event to scan and add q tags to
 * @return NOSTR_OK on success, error code otherwise
 *
 * Tag formats:
 * - note:   ["q", "<event-id-hex>", "", ""]
 * - nevent: ["q", "<event-id-hex>", "<relay-if-available>", "<pubkey-if-available>"]
 * - naddr:  ["q", "<kind:pubkey:d-tag>", "<relay-if-available>", ""]
 */
nostr_error_t nostr_quote_tags_from_content(nostr_event* event);

#define NOSTR_URI_MAX_RELAYS 16
#define NOSTR_URI_MAX_RELAY_LEN 256
#define NOSTR_URI_MAX_IDENTIFIER_LEN 256

typedef enum {
    NOSTR_URI_NPUB,
    NOSTR_URI_NSEC,
    NOSTR_URI_NOTE,
    NOSTR_URI_NPROFILE,
    NOSTR_URI_NEVENT,
    NOSTR_URI_NADDR,
    NOSTR_URI_NRELAY
} nostr_uri_type;

typedef struct nostr_nprofile {
    nostr_key pubkey;
    char* relays[NOSTR_URI_MAX_RELAYS];
    size_t relay_count;
} nostr_nprofile;

typedef struct nostr_nevent {
    uint8_t id[NOSTR_ID_SIZE];
    char* relays[NOSTR_URI_MAX_RELAYS];
    size_t relay_count;
    nostr_key author;
    int has_author;
    uint32_t kind;
    int has_kind;
} nostr_nevent;

typedef struct nostr_naddr {
    char identifier[NOSTR_URI_MAX_IDENTIFIER_LEN];
    nostr_key pubkey;
    uint32_t kind;
    char* relays[NOSTR_URI_MAX_RELAYS];
    size_t relay_count;
} nostr_naddr;

typedef struct nostr_nrelay {
    char url[NOSTR_URI_MAX_RELAY_LEN];
} nostr_nrelay;

typedef struct nostr_uri {
    nostr_uri_type type;
    union {
        nostr_key npub;
        nostr_privkey nsec;
        uint8_t note[NOSTR_ID_SIZE];
        nostr_nprofile nprofile;
        nostr_nevent nevent;
        nostr_naddr naddr;
        nostr_nrelay nrelay;
    } data;
} nostr_uri;

nostr_error_t nostr_uri_parse(const char* uri, nostr_uri* result);
nostr_error_t nostr_uri_encode(const nostr_uri* uri, char* output, size_t output_size);
void nostr_uri_free(nostr_uri* uri);

nostr_error_t nostr_nprofile_encode(const nostr_nprofile* profile, char* bech32, size_t bech32_size);
nostr_error_t nostr_nprofile_decode(const char* bech32, nostr_nprofile* profile);
void nostr_nprofile_free(nostr_nprofile* profile);

nostr_error_t nostr_nevent_encode(const nostr_nevent* event, char* bech32, size_t bech32_size);
nostr_error_t nostr_nevent_decode(const char* bech32, nostr_nevent* nevent);
void nostr_nevent_free(nostr_nevent* nevent);

nostr_error_t nostr_naddr_encode(const nostr_naddr* addr, char* bech32, size_t bech32_size);
nostr_error_t nostr_naddr_decode(const char* bech32, nostr_naddr* addr);
void nostr_naddr_free(nostr_naddr* addr);

nostr_error_t nostr_nrelay_encode(const nostr_nrelay* relay, char* bech32, size_t bech32_size);
nostr_error_t nostr_nrelay_decode(const char* bech32, nostr_nrelay* relay);

/**
 * @brief Encrypt a private key with a password (NIP-49)
 * @param privkey Private key to encrypt
 * @param password Password for encryption (caller should NFKC normalize for interop)
 * @param log_n Scrypt log_n parameter (16-22, higher = more secure but slower)
 * @param ncryptsec Output buffer for ncryptsec string
 * @param ncryptsec_size Size of ncryptsec buffer (at least 163 bytes: 162 chars + NUL)
 * @return NOSTR_OK on success, error code otherwise
 * @note Memory requirements: log_n=16: 64MB, log_n=18: 256MB, log_n=20: 1GB, log_n=22: 4GB
 * @note Caller is responsible for NFKC normalizing passwords and wiping after use
 */
nostr_error_t nostr_ncryptsec_encrypt(const nostr_privkey* privkey,
                                       const char* password,
                                       uint8_t log_n,
                                       char* ncryptsec,
                                       size_t ncryptsec_size);

/**
 * @brief Decrypt an ncryptsec string to recover the private key (NIP-49)
 * @param ncryptsec Encrypted key string (ncryptsec1...)
 * @param password Password for decryption (caller should NFKC normalize for interop)
 * @param privkey Output private key
 * @return NOSTR_OK on success, NOSTR_ERR_INVALID_SIGNATURE if password wrong
 * @note Caller is responsible for NFKC normalizing passwords and wiping after use
 */
nostr_error_t nostr_ncryptsec_decrypt(const char* ncryptsec,
                                       const char* password,
                                       nostr_privkey* privkey);

/**
 * @brief Validate an ncryptsec string format (NIP-49)
 * @param ncryptsec String to validate
 * @return NOSTR_OK if valid format, error code otherwise
 */
nostr_error_t nostr_ncryptsec_validate(const char* ncryptsec);

/*
 * NIP-65: Relay List Metadata
 *
 * Thread safety: nostr_relay_list is NOT thread-safe. Callers must provide
 * external synchronization if a list is accessed from multiple threads.
 * Invalid URLs in from_event are silently skipped to allow partial parsing.
 */

typedef struct nostr_relay_list_entry {
    char* url;
    bool read;
    bool write;
} nostr_relay_list_entry;

typedef struct nostr_relay_list {
    nostr_relay_list_entry* relays;
    size_t count;
    size_t capacity;
} nostr_relay_list;

nostr_error_t nostr_relay_list_create(nostr_relay_list** list);
void nostr_relay_list_free(nostr_relay_list* list);
nostr_error_t nostr_relay_list_add(nostr_relay_list* list, const char* url, bool read, bool write);
nostr_error_t nostr_relay_list_to_event(const nostr_relay_list* list, nostr_event** event);
nostr_error_t nostr_relay_list_from_event(const nostr_event* event, nostr_relay_list** list);
size_t nostr_relay_list_count(const nostr_relay_list* list);
const nostr_relay_list_entry* nostr_relay_list_get(const nostr_relay_list* list, size_t index);
nostr_error_t nostr_relay_list_get_read_relays(const nostr_relay_list* list, char*** urls, size_t* count);
nostr_error_t nostr_relay_list_get_write_relays(const nostr_relay_list* list, char*** urls, size_t* count);
void nostr_relay_list_free_urls(char** urls, size_t count);

/**
 * @brief HTTP callback for fetching .well-known/nostr.json
 * @note Callers MUST NOT follow HTTP redirects per NIP-05 security constraints
 */
typedef nostr_error_t (*nostr_nip05_http_callback)(const char* url, char** response,
                                                    size_t* response_len, void* user_data);

/** @brief Parse NIP-05 identifier into name and domain components */
nostr_error_t nostr_nip05_parse(const char* identifier, char* name, size_t name_size,
                                char* domain, size_t domain_size);

/** @brief Build .well-known/nostr.json verification URL from name and domain */
nostr_error_t nostr_nip05_build_url(const char* name, const char* domain,
                                    char* url, size_t url_size);

/** @brief Parse JSON response, extract pubkey and optional relays */
nostr_error_t nostr_nip05_parse_response(const char* json, const char* name,
                                         char* pubkey_hex, size_t pubkey_size,
                                         char*** relays, size_t* relay_count);

/** @brief Free relay array returned by nostr_nip05_parse_response */
void nostr_nip05_free_relays(char** relays, size_t count);

/** @brief Full NIP-05 verification flow: parse, fetch, and verify pubkey */
nostr_error_t nostr_nip05_verify(const char* identifier, const char* expected_pubkey,
                                 nostr_nip05_http_callback http_callback, void* user_data,
                                 char*** relays_out, size_t* relay_count_out);

/**
 * @brief Parsed delegation conditions from condition string
 */
typedef struct nostr_delegation_conditions {
    uint16_t* kinds;
    size_t kind_count;
    int64_t created_after;
    int64_t created_before;
    int has_created_after;
    int has_created_before;
} nostr_delegation_conditions;

/**
 * @brief NIP-26 Delegation structure
 */
typedef struct nostr_delegation {
    nostr_key delegator_pubkey;
    char* conditions;
    uint8_t token[NOSTR_SIG_SIZE];
    nostr_delegation_conditions parsed_conditions;
} nostr_delegation;

/**
 * @brief Create a delegation token (NIP-26)
 * @param delegator_privkey Delegator's private key (signs the delegation)
 * @param delegatee_pubkey Delegatee's public key (authorized to sign events)
 * @param conditions Condition query string (e.g., "kind=1&created_at>123")
 * @param delegation Output delegation structure
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_delegation_create(const nostr_privkey* delegator_privkey,
                                      const nostr_key* delegatee_pubkey,
                                      const char* conditions,
                                      nostr_delegation* delegation);

/**
 * @brief Verify a delegation token (NIP-26)
 * @param delegation Delegation to verify
 * @param delegatee_pubkey Expected delegatee's public key
 * @return NOSTR_OK if valid, NOSTR_ERR_INVALID_SIGNATURE otherwise
 */
nostr_error_t nostr_delegation_verify(const nostr_delegation* delegation,
                                      const nostr_key* delegatee_pubkey);

/**
 * @brief Check if event parameters satisfy delegation conditions (NIP-26)
 * @param delegation Delegation with parsed conditions
 * @param event_kind Event kind to check
 * @param created_at Event timestamp to check
 * @return NOSTR_OK if conditions satisfied, NOSTR_ERR_INVALID_EVENT otherwise
 */
nostr_error_t nostr_delegation_check_conditions(const nostr_delegation* delegation,
                                                uint16_t event_kind,
                                                int64_t created_at);

/**
 * @brief Add delegation tag to an event (NIP-26)
 * @param event Event to add delegation tag to
 * @param delegation Delegation to add
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_add_delegation(nostr_event* event,
                                         const nostr_delegation* delegation);

/**
 * @brief Extract delegation from an event's tags (NIP-26)
 * @param event Event to extract delegation from
 * @param delegation Output delegation structure (caller must call nostr_delegation_free)
 * @return NOSTR_OK if found, NOSTR_ERR_NOT_FOUND if no delegation tag
 */
nostr_error_t nostr_event_get_delegation(const nostr_event* event,
                                         nostr_delegation* delegation);

/**
 * @brief Verify event's delegation tag is valid (NIP-26)
 * @param event Event with delegation tag to verify
 * @return NOSTR_OK if valid, error code otherwise
 */
nostr_error_t nostr_event_verify_delegation(const nostr_event* event);

/**
 * @brief Free resources allocated in a delegation structure (NIP-26)
 * @param delegation Delegation to free
 */
void nostr_delegation_free(nostr_delegation* delegation);

typedef enum {
    NOSTR_LIST_KIND_MUTE = 10000,
    NOSTR_LIST_KIND_PIN = 10001,
    NOSTR_LIST_KIND_BOOKMARK = 10003,
    NOSTR_LIST_KIND_COMMUNITIES = 10004,
    NOSTR_LIST_KIND_PUBLIC_CHATS = 10005,
    NOSTR_LIST_KIND_BLOCKED_RELAYS = 10006,
    NOSTR_LIST_KIND_SEARCH_RELAYS = 10007,
    NOSTR_LIST_KIND_SIMPLE_GROUPS = 10009,
    NOSTR_LIST_KIND_RELAY_FEEDS = 10012,
    NOSTR_LIST_KIND_INTERESTS = 10015,
    NOSTR_LIST_KIND_MEDIA_FOLLOWS = 10020,
    NOSTR_LIST_KIND_EMOJIS = 10030,
    NOSTR_LIST_KIND_DM_RELAYS = 10050,
    NOSTR_LIST_KIND_GOOD_WIKI_AUTHORS = 10101,
    NOSTR_LIST_KIND_GOOD_WIKI_RELAYS = 10102,
    NOSTR_LIST_KIND_FOLLOW_SET = 30000,
    NOSTR_LIST_KIND_RELAY_SET = 30002,
    NOSTR_LIST_KIND_BOOKMARK_SET = 30003,
    NOSTR_LIST_KIND_CURATION_SET = 30004,
    NOSTR_LIST_KIND_CURATION_SET_VIDEOS = 30005,
    NOSTR_LIST_KIND_CURATION_SET_PICTURES = 30006,
    NOSTR_LIST_KIND_KIND_MUTE_SET = 30007,
    NOSTR_LIST_KIND_INTEREST_SET = 30015,
    NOSTR_LIST_KIND_EMOJI_SET = 30030,
    NOSTR_LIST_KIND_RELEASE_ARTIFACT_SET = 30063,
    NOSTR_LIST_KIND_APP_CURATION_SET = 30267,
    NOSTR_LIST_KIND_CALENDAR = 31924,
    NOSTR_LIST_KIND_STARTER_PACK = 39089,
    NOSTR_LIST_KIND_MEDIA_STARTER_PACK = 39092
} nostr_list_kind;

typedef struct nostr_list_item {
    char* tag_type;
    char* value;
    char* relay_hint;
    char* petname;
    bool is_private;
} nostr_list_item;

typedef struct nostr_list {
    uint16_t kind;
    char* d_tag;
    char* title;
    char* description;
    char* image;
    nostr_list_item* items;
    size_t item_count;
    size_t item_capacity;
} nostr_list;

nostr_error_t nostr_list_create(nostr_list** list, uint16_t kind);
void nostr_list_free(nostr_list* list);

nostr_error_t nostr_list_set_d_tag(nostr_list* list, const char* d_tag);
nostr_error_t nostr_list_set_title(nostr_list* list, const char* title);
nostr_error_t nostr_list_set_description(nostr_list* list, const char* description);
nostr_error_t nostr_list_set_image(nostr_list* list, const char* image);

nostr_error_t nostr_list_add_pubkey(nostr_list* list, const char* pubkey,
                                    const char* relay_hint, const char* petname, bool is_private);
nostr_error_t nostr_list_add_event(nostr_list* list, const char* event_id,
                                   const char* relay_hint, bool is_private);
nostr_error_t nostr_list_add_hashtag(nostr_list* list, const char* hashtag, bool is_private);
nostr_error_t nostr_list_add_word(nostr_list* list, const char* word, bool is_private);
nostr_error_t nostr_list_add_relay(nostr_list* list, const char* relay_url, bool is_private);
nostr_error_t nostr_list_add_reference(nostr_list* list, const char* reference,
                                       const char* relay_hint, bool is_private);
nostr_error_t nostr_list_add_group(nostr_list* list, const char* group_id,
                                   const char* relay_url, const char* group_name, bool is_private);
nostr_error_t nostr_list_add_emoji(nostr_list* list, const char* shortcode,
                                   const char* image_url, bool is_private);

nostr_error_t nostr_list_to_event(const nostr_list* list, const nostr_keypair* keypair,
                                  nostr_event** event);
nostr_error_t nostr_list_from_event(const nostr_event* event, const nostr_keypair* keypair,
                                    nostr_list** list);

size_t nostr_list_count(const nostr_list* list);
const nostr_list_item* nostr_list_get(const nostr_list* list, size_t index);
nostr_error_t nostr_list_remove(nostr_list* list, size_t index);

#ifdef __cplusplus
}
#endif

#endif