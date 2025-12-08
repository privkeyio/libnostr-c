/**
 * @file nostr_relay_protocol.h
 * @brief NIP-01 Relay-side protocol support for libnostr-c
 *
 * This header provides data structures and functions for relay implementations
 * to parse client messages, validate events, match filters, and serialize
 * relay responses according to NIP-01.
 *
 * Design principles:
 * - All functions are stateless and pure where possible
 * - Memory allocation via caller-provided buffers or explicit alloc/free pairs
 * - Return error codes, not exceptions
 * - JSON parsing/serialization uses cJSON
 */

#ifndef NOSTR_RELAY_PROTOCOL_H
#define NOSTR_RELAY_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "nostr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Error Codes (extends nostr_error_t for relay-specific errors)
 * ============================================================================ */

/**
 * @brief Extended error codes for relay protocol operations
 */
typedef enum {
    NOSTR_RELAY_OK = 0,
    NOSTR_RELAY_ERR_INVALID_JSON,
    NOSTR_RELAY_ERR_MISSING_FIELD,
    NOSTR_RELAY_ERR_INVALID_ID,
    NOSTR_RELAY_ERR_INVALID_PUBKEY,
    NOSTR_RELAY_ERR_INVALID_SIG,
    NOSTR_RELAY_ERR_INVALID_CREATED_AT,
    NOSTR_RELAY_ERR_INVALID_KIND,
    NOSTR_RELAY_ERR_INVALID_TAGS,
    NOSTR_RELAY_ERR_INVALID_CONTENT,
    NOSTR_RELAY_ERR_ID_MISMATCH,
    NOSTR_RELAY_ERR_SIG_MISMATCH,
    NOSTR_RELAY_ERR_FUTURE_EVENT,
    NOSTR_RELAY_ERR_EXPIRED_EVENT,
    NOSTR_RELAY_ERR_INVALID_SUBSCRIPTION_ID,
    NOSTR_RELAY_ERR_TOO_MANY_FILTERS,
    NOSTR_RELAY_ERR_BUFFER_TOO_SMALL,
    NOSTR_RELAY_ERR_MEMORY,
    NOSTR_RELAY_ERR_UNKNOWN_MESSAGE_TYPE
} nostr_relay_error_t;

/* ============================================================================
 * OK Message Prefixes (NIP-01)
 * ============================================================================ */

#define NOSTR_OK_PREFIX_DUPLICATE     "duplicate:"
#define NOSTR_OK_PREFIX_POW           "pow:"
#define NOSTR_OK_PREFIX_BLOCKED       "blocked:"
#define NOSTR_OK_PREFIX_RATE_LIMITED  "rate-limited:"
#define NOSTR_OK_PREFIX_INVALID       "invalid:"
#define NOSTR_OK_PREFIX_ERROR         "error:"
#define NOSTR_OK_PREFIX_AUTH_REQUIRED "auth-required:"
#define NOSTR_OK_PREFIX_RESTRICTED    "restricted:"

/* ============================================================================
 * Event Kind Classification (NIP-01)
 * ============================================================================ */

/**
 * @brief Event kind classification for storage behavior
 */
typedef enum {
    NOSTR_KIND_REGULAR,       /**< 1, 2, 4-44, 1000-9999: store all */
    NOSTR_KIND_REPLACEABLE,   /**< 0, 3, 10000-19999: latest per pubkey+kind */
    NOSTR_KIND_EPHEMERAL,     /**< 20000-29999: never store */
    NOSTR_KIND_ADDRESSABLE    /**< 30000-39999: latest per pubkey+kind+d-tag */
} nostr_kind_type_t;

/* ============================================================================
 * Validation Result
 * ============================================================================ */

/**
 * @brief Detailed validation result structure
 */
typedef struct {
    bool valid;                 /**< Overall validation result */
    nostr_relay_error_t error_code; /**< Error code if invalid */
    char error_message[256];    /**< Human-readable error message */
    char error_field[64];       /**< Which field failed validation */
} nostr_validation_result_t;

/* ============================================================================
 * Filter Structure (NIP-01)
 * ============================================================================ */

/**
 * @brief Single-letter generic tag filter entry
 */
typedef struct {
    char tag_name;              /**< Tag letter (a-zA-Z) */
    char** values;              /**< Tag values to match */
    size_t values_count;        /**< Number of values */
} nostr_generic_tag_filter_t;

/**
 * @brief Filter structure for subscription matching (NIP-01)
 */
typedef struct {
    char** ids;                 /**< Event ID prefixes to match */
    size_t ids_count;
    char** authors;             /**< Author pubkey prefixes to match */
    size_t authors_count;
    int32_t* kinds;             /**< Kind numbers to match */
    size_t kinds_count;
    char** e_tags;              /**< #e tag values (event IDs) */
    size_t e_tags_count;
    char** p_tags;              /**< #p tag values (pubkeys) */
    size_t p_tags_count;
    nostr_generic_tag_filter_t* generic_tags; /**< Generic single-letter tag filters */
    size_t generic_tags_count;
    int64_t since;              /**< Minimum created_at (0 = no limit) */
    int64_t until;              /**< Maximum created_at (0 = no limit) */
    int32_t limit;              /**< Max events to return (0 = no limit) */
} nostr_filter_t;

/* ============================================================================
 * Client Message Types and Structures
 * ============================================================================ */

/**
 * @brief Client message types
 */
typedef enum {
    NOSTR_CLIENT_MSG_EVENT,     /**< ["EVENT", <event>] */
    NOSTR_CLIENT_MSG_REQ,       /**< ["REQ", <sub_id>, <filters...>] */
    NOSTR_CLIENT_MSG_CLOSE,     /**< ["CLOSE", <sub_id>] */
    NOSTR_CLIENT_MSG_AUTH,      /**< ["AUTH", <event>] (NIP-42) */
    NOSTR_CLIENT_MSG_UNKNOWN    /**< Unknown message type */
} nostr_client_msg_type_t;

/**
 * @brief Parsed client message
 */
typedef struct {
    nostr_client_msg_type_t type;
    union {
        struct {
            nostr_event* event;         /**< EVENT message: the event */
        } event;
        struct {
            char subscription_id[65];   /**< REQ: subscription ID */
            nostr_filter_t* filters;    /**< REQ: array of filters */
            size_t filters_count;       /**< REQ: number of filters */
        } req;
        struct {
            char subscription_id[65];   /**< CLOSE: subscription ID */
        } close;
        struct {
            nostr_event* event;         /**< AUTH: auth event */
        } auth;
    } data;
} nostr_client_msg_t;

/* ============================================================================
 * Relay Message Types and Structures
 * ============================================================================ */

/**
 * @brief Relay message types
 */
typedef enum {
    NOSTR_RELAY_MSG_EVENT,      /**< ["EVENT", <sub_id>, <event>] */
    NOSTR_RELAY_MSG_OK,         /**< ["OK", <event_id>, <success>, <message>] */
    NOSTR_RELAY_MSG_EOSE,       /**< ["EOSE", <sub_id>] */
    NOSTR_RELAY_MSG_CLOSED,     /**< ["CLOSED", <sub_id>, <message>] */
    NOSTR_RELAY_MSG_NOTICE,     /**< ["NOTICE", <message>] */
    NOSTR_RELAY_MSG_AUTH        /**< ["AUTH", <challenge>] (NIP-42) */
} nostr_relay_msg_type_t;

/**
 * @brief Relay message structure for serialization
 */
typedef struct {
    nostr_relay_msg_type_t type;
    union {
        struct {
            char subscription_id[65];
            const nostr_event* event;   /**< Pointer to event (not owned) */
        } event;
        struct {
            char event_id[65];          /**< Hex event ID */
            bool success;
            char message[256];
        } ok;
        struct {
            char subscription_id[65];
        } eose;
        struct {
            char subscription_id[65];
            char message[256];
        } closed;
        struct {
            char message[256];
        } notice;
        struct {
            char challenge[128];
        } auth;
    } data;
} nostr_relay_msg_t;

/* ============================================================================
 * Filter Functions (NIP-01)
 * ============================================================================ */

/**
 * @brief Parse a single filter from JSON
 * @param json JSON string containing the filter object
 * @param json_len Length of JSON string
 * @param filter Output filter structure
 * @return NOSTR_RELAY_OK on success, error code otherwise
 * @note Caller must call nostr_filter_free() when done
 */
nostr_relay_error_t nostr_filter_parse(const char* json, size_t json_len, nostr_filter_t* filter);

/**
 * @brief Check if an event matches a single filter
 * @param filter Filter to check against
 * @param event Event to check
 * @return true if event matches filter, false otherwise
 */
bool nostr_filter_matches(const nostr_filter_t* filter, const nostr_event* event);

/**
 * @brief Check if an event matches any filter in an array (OR logic)
 * @param filters Array of filters
 * @param count Number of filters
 * @param event Event to check
 * @return true if event matches any filter, false otherwise
 */
bool nostr_filters_match(const nostr_filter_t* filters, size_t count, const nostr_event* event);

/**
 * @brief Validate a filter structure
 * @param filter Filter to validate
 * @param result Output validation result
 * @return NOSTR_RELAY_OK if valid, error code otherwise
 */
nostr_relay_error_t nostr_filter_validate(const nostr_filter_t* filter, nostr_validation_result_t* result);

/**
 * @brief Free filter internals
 * @param filter Filter to free
 */
void nostr_filter_free(nostr_filter_t* filter);

/* ============================================================================
 * Client Message Parsing (NIP-01)
 * ============================================================================ */

/**
 * @brief Parse any client message: EVENT, REQ, CLOSE, AUTH
 * @param json JSON array string from client
 * @param json_len Length of JSON string
 * @param msg Output parsed message
 * @return NOSTR_RELAY_OK on success, error code otherwise
 * @note Caller must call nostr_client_msg_free() when done
 */
nostr_relay_error_t nostr_client_msg_parse(const char* json, size_t json_len, nostr_client_msg_t* msg);

/**
 * @brief Free client message internals
 * @param msg Message to free
 */
void nostr_client_msg_free(nostr_client_msg_t* msg);

/* ============================================================================
 * Relay Message Serialization (NIP-01)
 * ============================================================================ */

/**
 * @brief Serialize a relay message to JSON
 * @param msg Message to serialize
 * @param buf Output buffer
 * @param buf_size Size of output buffer
 * @param out_len Output: actual length written (excluding null terminator)
 * @return NOSTR_RELAY_OK on success, NOSTR_RELAY_ERR_BUFFER_TOO_SMALL if buffer too small
 */
nostr_relay_error_t nostr_relay_msg_serialize(const nostr_relay_msg_t* msg, char* buf, size_t buf_size, size_t* out_len);

/**
 * @brief Convenience: initialize EVENT relay message
 */
void nostr_relay_msg_event(nostr_relay_msg_t* msg, const char* sub_id, const nostr_event* event);

/**
 * @brief Convenience: initialize OK relay message
 */
void nostr_relay_msg_ok(nostr_relay_msg_t* msg, const char* event_id, bool success, const char* message);

/**
 * @brief Convenience: initialize EOSE relay message
 */
void nostr_relay_msg_eose(nostr_relay_msg_t* msg, const char* sub_id);

/**
 * @brief Convenience: initialize CLOSED relay message
 */
void nostr_relay_msg_closed(nostr_relay_msg_t* msg, const char* sub_id, const char* message);

/**
 * @brief Convenience: initialize NOTICE relay message
 */
void nostr_relay_msg_notice(nostr_relay_msg_t* msg, const char* message);

/**
 * @brief Convenience: initialize AUTH relay message (NIP-42)
 */
void nostr_relay_msg_auth(nostr_relay_msg_t* msg, const char* challenge);

/* ============================================================================
 * Event Parsing and Serialization (NIP-01)
 * ============================================================================ */

/**
 * @brief Parse an event from JSON
 * @param json JSON string containing the event object
 * @param json_len Length of JSON string
 * @param event Output event pointer (caller must free with nostr_event_destroy)
 * @return NOSTR_RELAY_OK on success, error code otherwise
 */
nostr_relay_error_t nostr_event_parse(const char* json, size_t json_len, nostr_event** event);

/**
 * @brief Serialize event to canonical JSON format for ID computation
 *
 * Produces the canonical serialization: [0,<pubkey>,<created_at>,<kind>,<tags>,<content>]
 * This format is used for computing the event ID (SHA256 hash).
 *
 * @param event Event to serialize
 * @param buf Output buffer
 * @param buf_size Size of output buffer
 * @param out_len Output: actual length written (excluding null terminator)
 * @return NOSTR_RELAY_OK on success, NOSTR_RELAY_ERR_BUFFER_TOO_SMALL if buffer too small
 */
nostr_relay_error_t nostr_event_serialize_canonical(const nostr_event* event, char* buf, size_t buf_size, size_t* out_len);

/**
 * @brief Serialize event to full JSON format
 *
 * Produces the complete event JSON with all fields including id and sig.
 *
 * @param event Event to serialize
 * @param buf Output buffer
 * @param buf_size Size of output buffer
 * @param out_len Output: actual length written (excluding null terminator)
 * @return NOSTR_RELAY_OK on success, NOSTR_RELAY_ERR_BUFFER_TOO_SMALL if buffer too small
 */
nostr_relay_error_t nostr_event_serialize(const nostr_event* event, char* buf, size_t buf_size, size_t* out_len);

/* ============================================================================
 * Event Kind Classification (NIP-01)
 * ============================================================================ */

/**
 * @brief Get the classification type for an event kind
 * @param kind Event kind number
 * @return Kind classification type
 */
nostr_kind_type_t nostr_kind_get_type(int32_t kind);

/**
 * @brief Check if a kind is regular (stored normally)
 */
bool nostr_kind_is_regular(int32_t kind);

/**
 * @brief Check if a kind is replaceable (latest per pubkey+kind)
 */
bool nostr_kind_is_replaceable(int32_t kind);

/**
 * @brief Check if a kind is ephemeral (never stored)
 */
bool nostr_kind_is_ephemeral(int32_t kind);

/**
 * @brief Check if a kind is addressable (latest per pubkey+kind+d-tag)
 */
bool nostr_kind_is_addressable(int32_t kind);

/* ============================================================================
 * Event Validation (NIP-01)
 * ============================================================================ */

/**
 * @brief Validate an event fully (structure + ID + signature + timestamp)
 * @param event Event to validate
 * @param max_future_seconds Maximum seconds in future allowed (e.g., 900 for 15 min)
 * @param result Output validation result
 * @return NOSTR_RELAY_OK if valid, error code otherwise
 */
nostr_relay_error_t nostr_event_validate_full(const nostr_event* event, int64_t max_future_seconds, nostr_validation_result_t* result);

/**
 * @brief Compare replaceable events (same pubkey+kind)
 * @param a First event
 * @param b Second event
 * @return -1 if a is older, 0 if same age, 1 if a is newer
 * @note When timestamps are equal, lower ID (lexicographically) is considered newer
 */
int nostr_event_compare_replaceable(const nostr_event* a, const nostr_event* b);

/**
 * @brief Compare addressable events (same pubkey+kind+d-tag)
 * @param a First event
 * @param b Second event
 * @return -1 if a is older, 0 if same age, 1 if a is newer
 */
int nostr_event_compare_addressable(const nostr_event* a, const nostr_event* b);

/* ============================================================================
 * Tag Utilities
 * ============================================================================ */

/**
 * @brief Get first tag value by tag name
 * @param event Event to search
 * @param tag_name Tag name (e.g., "e", "p", "d")
 * @return Pointer to tag value, or NULL if not found
 */
const char* nostr_event_get_tag_value(const nostr_event* event, const char* tag_name);

/**
 * @brief Get the d-tag value for addressable events
 * @param event Event to search
 * @return Pointer to d-tag value, or NULL if not found
 */
const char* nostr_event_get_d_tag(const nostr_event* event);

/**
 * @brief Get all values for a specific tag name
 * @param event Event to search
 * @param tag_name Tag name to find
 * @param values Output array (caller provides)
 * @param max_values Maximum values to return
 * @return Number of values found and copied
 */
size_t nostr_event_get_tag_values(const nostr_event* event, const char* tag_name, const char** values, size_t max_values);

/**
 * @brief Check if event has a specific tag
 * @param event Event to search
 * @param tag_name Tag name to find
 * @return true if tag exists, false otherwise
 */
bool nostr_event_has_tag(const nostr_event* event, const char* tag_name);

/**
 * @brief Get tag at specific index
 * @param event Event
 * @param index Tag index
 * @param out_count Output: number of values in tag
 * @return Pointer to values array, or NULL if out of bounds
 */
const char** nostr_event_get_tag_at(const nostr_event* event, size_t index, size_t* out_count);

/* ============================================================================
 * Validation Utilities
 * ============================================================================ */

/**
 * @brief Validate a 64-character lowercase hex string
 * @param hex String to validate
 * @return true if valid, false otherwise
 */
bool nostr_validate_hex64(const char* hex);

/**
 * @brief Validate a hex prefix (1-64 chars, lowercase)
 * @param hex String to validate
 * @return true if valid, false otherwise
 */
bool nostr_validate_hex_prefix(const char* hex);

/**
 * @brief Validate a subscription ID (1-64 chars, printable, non-empty)
 * @param sub_id String to validate
 * @return true if valid, false otherwise
 */
bool nostr_validate_subscription_id(const char* sub_id);

/**
 * @brief Validate a timestamp (not too far in future)
 * @param timestamp Unix timestamp to validate
 * @param max_future_seconds Maximum seconds in future allowed
 * @return true if valid, false otherwise
 */
bool nostr_validate_timestamp(int64_t timestamp, int64_t max_future_seconds);

/**
 * @brief Get current Unix timestamp
 * @return Current Unix timestamp
 */
int64_t nostr_timestamp_now(void);

/* ============================================================================
 * Expiration (NIP-40)
 * ============================================================================ */

/**
 * @brief Get expiration timestamp from event
 * @param event Event to check
 * @return Expiration timestamp, or 0 if no expiration tag
 */
int64_t nostr_event_get_expiration(const nostr_event* event);

/**
 * @brief Check if event is expired relative to given timestamp
 * @param event Event to check
 * @param now Current timestamp
 * @return true if expired, false otherwise
 */
bool nostr_event_is_expired(const nostr_event* event, int64_t now);

/**
 * @brief Check if event is expired relative to current time
 * @param event Event to check
 * @return true if expired, false otherwise
 */
bool nostr_event_is_expired_now(const nostr_event* event);

/* ============================================================================
 * Error Handling
 * ============================================================================ */

/**
 * @brief Get human-readable error string
 * @param error Error code
 * @return Error message string
 */
const char* nostr_relay_error_string(nostr_relay_error_t error);

/**
 * @brief Format full validation error message
 * @param result Validation result
 * @param buf Output buffer
 * @param buf_size Size of output buffer
 * @return Number of characters written (excluding null terminator)
 * @note Example output: "invalid: signature verification failed for field 'sig'"
 */
size_t nostr_validation_error_format(const nostr_validation_result_t* result, char* buf, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif /* NOSTR_RELAY_PROTOCOL_H */
