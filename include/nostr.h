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

#ifdef __cplusplus
}
#endif

#endif