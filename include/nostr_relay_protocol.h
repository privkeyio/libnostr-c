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
    NOSTR_RELAY_ERR_UNKNOWN_MESSAGE_TYPE,
    NOSTR_RELAY_ERR_STORAGE
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
 * @brief Filter structure for subscription matching (NIP-01, NIP-50)
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
    char* search;               /**< NIP-50: search query string (NULL = no search) */
} nostr_filter_t;

/**
 * @brief Search matching callback for NIP-50 support
 * @param query The search query string from the filter
 * @param event The event to match against
 * @param user_data User-provided context data
 * @return true if event matches the search query, false otherwise
 */
typedef bool (*nostr_search_callback_t)(const char* query, const nostr_event* event, void* user_data);

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
    NOSTR_CLIENT_MSG_COUNT,     /**< ["COUNT", <query_id>, <filters...>] (NIP-45) */
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
        struct {
            char query_id[65];          /**< COUNT: query ID (NIP-45) */
            nostr_filter_t* filters;    /**< COUNT: array of filters */
            size_t filters_count;       /**< COUNT: number of filters */
        } count;
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
    NOSTR_RELAY_MSG_AUTH,       /**< ["AUTH", <challenge>] (NIP-42) */
    NOSTR_RELAY_MSG_COUNT       /**< ["COUNT", <query_id>, {"count": N}] (NIP-45) */
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
        struct {
            char query_id[65];          /**< Query ID (NIP-45) */
            int64_t count;              /**< Event count */
            bool approximate;           /**< Whether count is approximate */
        } count;
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
 * @note Search field (NIP-50) is ignored. Use nostr_filter_matches_with_search for search support.
 */
bool nostr_filter_matches(const nostr_filter_t* filter, const nostr_event* event);

/**
 * @brief Check if an event matches a filter with optional search callback (NIP-50)
 * @param filter Filter to check against
 * @param event Event to check
 * @param search_cb Callback for search matching. If NULL and filter has a non-empty search
 *                  field, the function returns false (no match). If filter has no search
 *                  field, callback is not invoked.
 * @param user_data User data passed to search callback
 * @return true if event matches filter, false otherwise
 */
bool nostr_filter_matches_with_search(const nostr_filter_t* filter, const nostr_event* event,
                                      nostr_search_callback_t search_cb, void* user_data);

/**
 * @brief Check if an event matches any filter in an array (OR logic)
 * @param filters Array of filters
 * @param count Number of filters
 * @param event Event to check
 * @return true if event matches any filter, false otherwise
 * @note Search fields (NIP-50) are ignored. Use nostr_filters_match_with_search for search support.
 */
bool nostr_filters_match(const nostr_filter_t* filters, size_t count, const nostr_event* event);

/**
 * @brief Check if an event matches any filter with optional search callback (NIP-50)
 * @param filters Array of filters
 * @param count Number of filters
 * @param event Event to check
 * @param search_cb Callback for search matching. If NULL, filters with non-empty search
 *                  fields will not match. Filters without search fields are unaffected.
 * @param user_data User data passed to search callback
 * @return true if event matches any filter, false otherwise
 */
bool nostr_filters_match_with_search(const nostr_filter_t* filters, size_t count, const nostr_event* event,
                                     nostr_search_callback_t search_cb, void* user_data);

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

/**
 * @brief Deep copy a filter
 * @param dst Destination filter (must be uninitialized or zeroed)
 * @param src Source filter to copy
 * @return NOSTR_RELAY_OK on success, error code otherwise
 * @note Caller must call nostr_filter_free() on dst when done
 */
nostr_relay_error_t nostr_filter_clone(nostr_filter_t* dst, const nostr_filter_t* src);

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

/**
 * @brief Convenience: initialize COUNT relay message (NIP-45)
 */
void nostr_relay_msg_count(nostr_relay_msg_t* msg, const char* query_id, int64_t count, bool approximate);

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
 * @brief Validate an addressable event coordinate (NIP-33 "a" tag format)
 * @param address String in format "<kind>:<pubkey>:<d-tag>"
 * @return true if valid, false otherwise
 */
bool nostr_validate_address(const char* address);

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
 * Event Deletion (NIP-09)
 * ============================================================================ */

/**
 * @brief Parsed deletion request from a kind 5 event
 */
typedef struct {
    char** event_ids;           /**< Array of event IDs to delete (hex strings) */
    size_t event_ids_count;     /**< Number of event IDs */
    char** addresses;           /**< Array of "a" tag addresses to delete (kind:pubkey:d-tag) */
    size_t addresses_count;     /**< Number of addresses */
    char pubkey[65];            /**< Pubkey of the deletion request author (hex) */
    char* reason;               /**< Optional deletion reason (content field) */
} nostr_deletion_request_t;

/**
 * @brief Parse a deletion event (kind 5) into a deletion request
 * @param event The kind 5 deletion event
 * @param request Output deletion request structure
 * @return NOSTR_RELAY_OK on success, error code otherwise
 * @note Caller must call nostr_deletion_free() when done
 */
nostr_relay_error_t nostr_deletion_parse(const nostr_event* event, nostr_deletion_request_t* request);

/**
 * @brief Check if a deletion request is authorized to delete an event
 *
 * Per NIP-09, a deletion is authorized if:
 * - The deletion event's pubkey matches the target event's pubkey
 * - The target event's ID is in the deletion request's "e" tags
 *
 * @param request The parsed deletion request
 * @param target_event The event to potentially delete
 * @return true if authorized to delete, false otherwise
 */
bool nostr_deletion_authorized(const nostr_deletion_request_t* request, const nostr_event* target_event);

/**
 * @brief Check if a deletion request is authorized to delete an addressable event
 *
 * Per NIP-09, a deletion is authorized for addressable events if:
 * - The deletion event's pubkey matches the target event's pubkey
 * - The target's address (kind:pubkey:d-tag) is in the deletion request's "a" tags
 *
 * @param request The parsed deletion request
 * @param target_event The addressable event to potentially delete
 * @return true if authorized to delete, false otherwise
 */
bool nostr_deletion_authorized_address(const nostr_deletion_request_t* request, const nostr_event* target_event);

/**
 * @brief Free deletion request internals
 * @param request Deletion request to free
 */
void nostr_deletion_free(nostr_deletion_request_t* request);

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

/* ============================================================================
 * NIP-11 Relay Information Document
 * ============================================================================ */

#define NOSTR_DEFAULT_MAX_MESSAGE_LENGTH    (128 * 1024)
#define NOSTR_DEFAULT_MAX_SUBSCRIPTIONS     20
#define NOSTR_DEFAULT_MAX_FILTERS           10
#define NOSTR_DEFAULT_MAX_LIMIT             5000
#define NOSTR_DEFAULT_MAX_SUBID_LENGTH      64
#define NOSTR_DEFAULT_MAX_EVENT_TAGS        2000
#define NOSTR_DEFAULT_MAX_CONTENT_LENGTH    (64 * 1024)
#define NOSTR_DEFAULT_DEFAULT_LIMIT         500
#define NOSTR_MAX_TAG_FILTER_VALUES         256

typedef struct {
    int32_t max_message_length;
    int32_t max_subscriptions;
    int32_t max_filters;
    int32_t max_limit;
    int32_t max_subid_length;
    int32_t max_event_tags;
    int32_t max_content_length;
    int32_t min_pow_difficulty;
    bool auth_required;
    bool payment_required;
    bool restricted_writes;
    int64_t created_at_lower_limit;
    int64_t created_at_upper_limit;
    int32_t default_limit;
} nostr_relay_limitation_t;

typedef struct {
    int32_t* kinds;
    size_t kinds_count;
    int64_t time;
    int32_t count;
} nostr_relay_retention_t;

typedef struct {
    uint64_t amount;
    const char* unit;
    uint32_t period;
    int32_t* kinds;
    size_t kinds_count;
} nostr_relay_fee_t;

typedef struct {
    nostr_relay_fee_t* admission;
    size_t admission_count;
    nostr_relay_fee_t* subscription;
    size_t subscription_count;
    nostr_relay_fee_t* publication;
    size_t publication_count;
} nostr_relay_fees_t;

typedef struct {
    const char* name;
    const char* description;
    const char* banner;
    const char* icon;
    const char* pubkey;
    const char* self_pubkey;
    const char* contact;
    int32_t* supported_nips;
    size_t supported_nips_count;
    const char* software;
    const char* version;
    const char* privacy_policy;
    const char* terms_of_service;
    nostr_relay_limitation_t limitation;
    nostr_relay_retention_t* retention;
    size_t retention_count;
    const char** relay_countries;
    size_t relay_countries_count;
    const char** language_tags;
    size_t language_tags_count;
    const char** tags;
    size_t tags_count;
    const char* posting_policy;
    const char* payments_url;
    nostr_relay_fees_t fees;
} nostr_relay_info_t;

void nostr_relay_info_init(nostr_relay_info_t* info);

void nostr_relay_limitation_init(nostr_relay_limitation_t* limitation);

nostr_relay_error_t nostr_relay_info_serialize(const nostr_relay_info_t* info,
                                               char* buf,
                                               size_t buf_size,
                                               size_t* out_len);

nostr_relay_error_t nostr_relay_limitation_serialize(const nostr_relay_limitation_t* limitation,
                                                     char* buf,
                                                     size_t buf_size,
                                                     size_t* out_len);

nostr_relay_error_t nostr_relay_info_set_nips(nostr_relay_info_t* info,
                                              const int32_t* nips,
                                              size_t count);

nostr_relay_error_t nostr_relay_info_add_nip(nostr_relay_info_t* info, int32_t nip);

void nostr_relay_info_free(nostr_relay_info_t* info);

/* ============================================================================
 * Tag Iteration for Indexing
 * ============================================================================ */

typedef struct {
    const nostr_event* event;
    size_t current_index;
} nostr_tag_iterator_t;

typedef struct {
    const char* name;
    const char** values;
    size_t values_count;
} nostr_tag_info_t;

void nostr_tag_iterator_init(nostr_tag_iterator_t* iter, const nostr_event* event);

const char** nostr_tag_iterator_next(nostr_tag_iterator_t* iter, size_t* tag_len);

bool nostr_tag_iterator_next_info(nostr_tag_iterator_t* iter, nostr_tag_info_t* tag);

bool nostr_tag_is_indexable(const char* tag_name);

/* ============================================================================
 * Filter Tag Accessors for Query Planning
 * ============================================================================ */

const char** nostr_filter_get_e_tags(const nostr_filter_t* filter, size_t* count);

const char** nostr_filter_get_p_tags(const nostr_filter_t* filter, size_t* count);

const char** nostr_filter_get_tag_values(const nostr_filter_t* filter,
                                         char tag_name,
                                         size_t* count);

bool nostr_filter_has_tag_filters(const nostr_filter_t* filter);

/* ============================================================================
 * Filter Accessor Functions
 * ============================================================================ */

/**
 * @brief Get IDs filter array (hex strings)
 * @param filter Filter to query
 * @param out_count Output: number of IDs
 * @return Pointer to IDs array, or NULL if not specified
 */
const char** nostr_filter_get_ids(const nostr_filter_t* filter, size_t* out_count);

/**
 * @brief Get authors filter array (hex strings)
 * @param filter Filter to query
 * @param out_count Output: number of authors
 * @return Pointer to authors array, or NULL if not specified
 */
const char** nostr_filter_get_authors(const nostr_filter_t* filter, size_t* out_count);

/**
 * @brief Get kinds filter array
 * @param filter Filter to query
 * @param out_count Output: number of kinds
 * @return Pointer to kinds array, or NULL if not specified
 */
const int32_t* nostr_filter_get_kinds(const nostr_filter_t* filter, size_t* out_count);

/**
 * @brief Get since timestamp
 * @param filter Filter to query
 * @return Since timestamp (0 if not specified)
 */
int64_t nostr_filter_get_since(const nostr_filter_t* filter);

/**
 * @brief Get until timestamp
 * @param filter Filter to query
 * @return Until timestamp (0 if not specified)
 */
int64_t nostr_filter_get_until(const nostr_filter_t* filter);

/**
 * @brief Get limit
 * @param filter Filter to query
 * @return Limit (0 if not specified)
 */
int32_t nostr_filter_get_limit(const nostr_filter_t* filter);

/**
 * @brief Get search query (NIP-50)
 * @param filter Filter to query
 * @return Search query string (NULL if not specified)
 */
const char* nostr_filter_get_search(const nostr_filter_t* filter);

/**
 * @brief Check if filter has a search query (NIP-50)
 * @param filter Filter to query
 * @return true if filter has search field, false otherwise
 */
bool nostr_filter_has_search(const nostr_filter_t* filter);

/* ============================================================================
 * Client Message Accessor Functions
 * ============================================================================ */

/**
 * @brief Get client message type
 * @param msg Message to query
 * @return Message type
 */
nostr_client_msg_type_t nostr_client_msg_get_type(const nostr_client_msg_t* msg);

/**
 * @brief Get event from EVENT or AUTH message
 * @param msg Message to query
 * @return Pointer to event (valid until msg freed), or NULL
 */
const nostr_event* nostr_client_msg_get_event(const nostr_client_msg_t* msg);

/**
 * @brief Get subscription ID from REQ or CLOSE message
 * @param msg Message to query
 * @return Pointer to subscription ID string, or NULL
 */
const char* nostr_client_msg_get_subscription_id(const nostr_client_msg_t* msg);

/**
 * @brief Get filters from REQ message
 * @param msg Message to query
 * @param out_count Output: number of filters
 * @return Pointer to filters array, or NULL
 */
const nostr_filter_t* nostr_client_msg_get_filters(const nostr_client_msg_t* msg, size_t* out_count);

/* ============================================================================
 * Event Accessor Functions
 * ============================================================================ */

/**
 * @brief Get binary event ID (32 bytes)
 * @param event Event to query
 * @return Pointer to 32-byte ID array
 */
const uint8_t* nostr_event_get_id(const nostr_event* event);

/**
 * @brief Get binary pubkey (32 bytes)
 * @param event Event to query
 * @return Pointer to 32-byte pubkey array
 */
const uint8_t* nostr_event_get_pubkey(const nostr_event* event);

/**
 * @brief Get event ID as hex string
 * @param event Event to query
 * @param out Buffer of at least 65 bytes
 */
void nostr_event_get_id_hex(const nostr_event* event, char* out);

/**
 * @brief Get pubkey as hex string
 * @param event Event to query
 * @param out Buffer of at least 65 bytes
 */
void nostr_event_get_pubkey_hex(const nostr_event* event, char* out);

/**
 * @brief Get number of tags
 * @param event Event to query
 * @return Number of tags
 */
size_t nostr_event_get_tag_count(const nostr_event* event);

/**
 * @brief Get tag at index
 * @param event Event to query
 * @param index Tag index
 * @return Pointer to tag, or NULL if out of bounds
 */
const nostr_tag* nostr_event_get_tag(const nostr_event* event, size_t index);

/**
 * @brief Get tag name (first element)
 * @param tag Tag to query
 * @return Tag name string, or NULL
 */
const char* nostr_tag_get_name(const nostr_tag* tag);

/**
 * @brief Get number of values in tag (including name)
 * @param tag Tag to query
 * @return Number of values
 */
size_t nostr_tag_get_value_count(const nostr_tag* tag);

/**
 * @brief Get tag value at index
 * @param tag Tag to query
 * @param index Value index (0 = name, 1+ = values)
 * @return Value string, or NULL if out of bounds
 */
const char* nostr_tag_get_value(const nostr_tag* tag, size_t index);

/**
 * @brief Find first tag with given name
 * @param event Event to search
 * @param tag_name Tag name to find
 * @return Pointer to tag, or NULL if not found
 */
const nostr_tag* nostr_event_find_tag(const nostr_event* event, const char* tag_name);

/**
 * @brief Check if event is a deletion request (kind 5)
 * @param event Event to check
 * @return true if kind 5, false otherwise
 */
bool nostr_event_is_deletion(const nostr_event* event);

/**
 * @brief Get all e-tag values as binary IDs
 * @param event Event to query
 * @param out_count Output: number of IDs found
 * @return Newly allocated array of 32-byte IDs, caller must free with nostr_free()
 */
uint8_t (*nostr_event_get_e_tags_binary(const nostr_event* event, size_t* out_count))[32];

/**
 * @brief Get all p-tag values as binary pubkeys
 * @param event Event to query
 * @param out_count Output: number of pubkeys found
 * @return Newly allocated array of 32-byte pubkeys, caller must free with nostr_free()
 */
uint8_t (*nostr_event_get_p_tags_binary(const nostr_event* event, size_t* out_count))[32];

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * @brief Convert hex string to bytes
 * @param hex Input hex string
 * @param hex_len Length of hex string
 * @param out Output byte buffer
 * @param out_size Size of output buffer
 * @return NOSTR_RELAY_OK on success, error code otherwise
 */
nostr_relay_error_t nostr_hex_to_bytes(const char* hex, size_t hex_len, uint8_t* out, size_t out_size);

/**
 * @brief Convert bytes to hex string
 * @param bytes Input bytes
 * @param bytes_len Number of bytes
 * @param out Output hex string buffer (must be at least bytes_len * 2 + 1)
 */
void nostr_bytes_to_hex(const uint8_t* bytes, size_t bytes_len, char* out);

/**
 * @brief Free memory allocated by libnostr-c relay functions
 * @param ptr Pointer to free
 */
void nostr_free(void* ptr);

/**
 * @brief Free string array allocated by libnostr-c
 * @param strings Array of strings
 * @param count Number of strings
 */
void nostr_free_strings(char** strings, size_t count);

/**
 * @brief Get library version string
 * @return Version string (e.g., "0.1.1")
 */
const char* nostr_version(void);

#ifdef __cplusplus
}
#endif

#endif /* NOSTR_RELAY_PROTOCOL_H */
