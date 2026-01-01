#include "nostr.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#ifdef HAVE_MBEDTLS
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#ifdef ESP_PLATFORM
#include <esp_random.h>
#endif
#else
#include <openssl/sha.h>
#include <openssl/rand.h>
#endif
#ifdef HAVE_NOSCRYPT
#include <noscrypt.h>
#endif
#ifdef HAVE_SECP256K1
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#endif

#ifdef NOSTR_FEATURE_JSON_ENHANCED
#include <cjson/cJSON.h>
#endif

#ifdef HAVE_NOSCRYPT
extern NCContext* nc_ctx;
#endif
#ifdef HAVE_SECP256K1
extern secp256k1_context* secp256k1_ctx;
#endif
extern nostr_error_t nostr_init(void);
extern int nostr_random_bytes(uint8_t *buf, size_t len);

static void event_sha256(const uint8_t *data, size_t len, uint8_t *hash) {
#ifdef HAVE_MBEDTLS
    mbedtls_sha256(data, len, hash, 0);
#else
    SHA256(data, len, hash);
#endif
}

static nostr_error_t tag_arena_create(nostr_tag_arena** arena, size_t initial_capacity)
{
    if (!arena) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    *arena = malloc(sizeof(nostr_tag_arena));
    if (!*arena) {
        return NOSTR_ERR_MEMORY;
    }
    
    (*arena)->memory = malloc(initial_capacity);
    if (!(*arena)->memory) {
        free(*arena);
        return NOSTR_ERR_MEMORY;
    }
    
    (*arena)->capacity = initial_capacity;
    (*arena)->used = 0;
    return NOSTR_OK;
}

static void tag_arena_destroy(nostr_tag_arena* arena)
{
    if (!arena) {
        return;
    }
    free(arena->memory);
    free(arena);
}

static void* tag_arena_alloc(nostr_tag_arena* arena, size_t size)
{
    if (!arena || arena->used + size > arena->capacity) {
        return NULL;
    }
    
    void* ptr = (char*)arena->memory + arena->used;
    arena->used += size;
    return ptr;
}

nostr_error_t nostr_event_create(nostr_event** event)
{
    if (!event) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    *event = calloc(1, sizeof(nostr_event));
    if (!*event) {
        return NOSTR_ERR_MEMORY;
    }

    if (tag_arena_create(&(*event)->tag_arena, 1024) != NOSTR_OK) {
        free(*event);
        return NOSTR_ERR_MEMORY;
    }

    (*event)->created_at = time(NULL);
    return NOSTR_OK;
}

void nostr_event_destroy(nostr_event* event)
{
    if (!event) {
        return;
    }

    free(event->content);
    tag_arena_destroy(event->tag_arena);
    free(event->tags);
    free(event);
}

nostr_error_t nostr_event_set_content(nostr_event* event, const char* content)
{
    if (!event || !content) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    free(event->content);
    event->content = strdup(content);
    if (!event->content) {
        return NOSTR_ERR_MEMORY;
    }

    return NOSTR_OK;
}

nostr_error_t nostr_event_add_tag(nostr_event* event, const char** values, size_t count)
{
    if (!event || !values || count == 0) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    size_t values_size = sizeof(char*) * count;
    size_t strings_size = 0;
    for (size_t i = 0; i < count; i++) {
        strings_size += strlen(values[i]) + 1;
    }
    
    size_t total_size = values_size + strings_size;
    
    if (event->tag_arena->used + total_size > event->tag_arena->capacity) {
        size_t new_capacity = event->tag_arena->capacity;
        while (new_capacity < event->tag_arena->used + total_size) {
            new_capacity *= 2;
        }
        
        void* old_memory = event->tag_arena->memory;
        void* new_memory = realloc(event->tag_arena->memory, new_capacity);
        if (!new_memory) {
            return NOSTR_ERR_MEMORY;
        }

        if (new_memory != old_memory) {
            ptrdiff_t offset = (char*)new_memory - (char*)old_memory;
            for (size_t i = 0; i < event->tags_count; i++) {
                // Update the values array pointer
                event->tags[i].values = (char**)((char*)event->tags[i].values + offset);
                // Update all string pointers within the values array
                for (size_t j = 0; j < event->tags[i].count; j++) {
                    event->tags[i].values[j] += offset;
                }
            }
        }

        event->tag_arena->memory = new_memory;
        event->tag_arena->capacity = new_capacity;
    }

    nostr_tag* new_tags = realloc(event->tags, sizeof(nostr_tag) * (event->tags_count + 1));
    if (!new_tags) {
        return NOSTR_ERR_MEMORY;
    }
    event->tags = new_tags;

    nostr_tag* tag = &event->tags[event->tags_count];
    
    tag->values = (char**)tag_arena_alloc(event->tag_arena, values_size);
    if (!tag->values) {
        return NOSTR_ERR_MEMORY;
    }
    
    char* string_storage = (char*)tag_arena_alloc(event->tag_arena, strings_size);
    if (!string_storage) {
        return NOSTR_ERR_MEMORY;
    }
    
    tag->count = count;
    for (size_t i = 0; i < count; i++) {
        size_t len = strlen(values[i]) + 1;
        memcpy(string_storage, values[i], len);
        tag->values[i] = string_storage;
        string_storage += len;
    }

    event->tags_count++;
    return NOSTR_OK;
}

static char* escape_json_string(const char* input)
{
    if (!input) return NULL;
    
    size_t len = strlen(input);
    size_t max_output_len = len * 2 + 1;
    char* output = malloc(max_output_len);
    if (!output) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        switch (input[i]) {
            case '"':
                output[j++] = '\\';
                output[j++] = '"';
                break;
            case '\\':
                output[j++] = '\\';
                output[j++] = '\\';
                break;
            case '\n':
                output[j++] = '\\';
                output[j++] = 'n';
                break;
            case '\r':
                output[j++] = '\\';
                output[j++] = 'r';
                break;
            case '\t':
                output[j++] = '\\';
                output[j++] = 't';
                break;
            case '\b':
                output[j++] = '\\';
                output[j++] = 'b';
                break;
            case '\f':
                output[j++] = '\\';
                output[j++] = 'f';
                break;
            default:
                output[j++] = input[i];
                break;
        }
    }
    output[j] = '\0';
    return output;
}

static char* serialize_for_id(const nostr_event* event)
{
#ifdef NOSTR_FEATURE_JSON_ENHANCED
    char pubkey_hex[65];
    const char* content = event->content ? event->content : "";

    for (int i = 0; i < NOSTR_PUBKEY_SIZE; i++) {
        sprintf(pubkey_hex + i * 2, "%02x", event->pubkey.data[i]);
    }
    pubkey_hex[64] = '\0';

    cJSON* serialization = cJSON_CreateArray();
    cJSON_AddItemToArray(serialization, cJSON_CreateNumber(0));
    cJSON_AddItemToArray(serialization, cJSON_CreateString(pubkey_hex));
    cJSON_AddItemToArray(serialization, cJSON_CreateNumber(event->created_at));
    cJSON_AddItemToArray(serialization, cJSON_CreateNumber(event->kind));

    cJSON* tags_array = cJSON_CreateArray();
    for (size_t i = 0; i < event->tags_count; i++) {
        cJSON* tag_array = cJSON_CreateArray();
        for (size_t j = 0; j < event->tags[i].count; j++) {
            const char* tag_value = event->tags[i].values[j] ? event->tags[i].values[j] : "";
            cJSON_AddItemToArray(tag_array, cJSON_CreateString(tag_value));
        }
        cJSON_AddItemToArray(tags_array, tag_array);
    }
    cJSON_AddItemToArray(serialization, tags_array);
    cJSON_AddItemToArray(serialization, cJSON_CreateString(content));

    char* result = cJSON_PrintUnformatted(serialization);

    cJSON_Delete(serialization);

    return result;
#else
    char pubkey_hex[65];
    char* content_escaped = escape_json_string(event->content ? event->content : "");
    
    for (int i = 0; i < NOSTR_PUBKEY_SIZE; i++) {
        sprintf(pubkey_hex + i * 2, "%02x", event->pubkey.data[i]);
    }
    pubkey_hex[64] = '\0';

    size_t json_size = 512 + strlen(content_escaped);
    for (size_t i = 0; i < event->tags_count; i++) {
        for (size_t j = 0; j < event->tags[i].count; j++) {
            json_size += strlen(event->tags[i].values[j]) + 4;
        }
    }
    
    char* result = malloc(json_size);
    if (!result) {
        free(content_escaped);
        return NULL;
    }
    
    int pos = snprintf(result, json_size, "[0,\"%s\",%" PRId64 ",%d,[", 
                      pubkey_hex, event->created_at, event->kind);
    
    for (size_t i = 0; i < event->tags_count; i++) {
        if (i > 0) result[pos++] = ',';
        result[pos++] = '[';
        for (size_t j = 0; j < event->tags[i].count; j++) {
            if (j > 0) result[pos++] = ',';
            pos += snprintf(result + pos, json_size - pos, "\"%s\"", event->tags[i].values[j]);
        }
        result[pos++] = ']';
    }
    
    pos += snprintf(result + pos, json_size - pos, "],\"%s\"]", content_escaped);
    
    free(content_escaped);
    return result;
#endif
}

nostr_error_t nostr_event_compute_id(nostr_event* event)
{
    if (!event) {
        return NOSTR_ERR_INVALID_PARAM;
    }

    char* serialized = serialize_for_id(event);
    if (!serialized) {
        return NOSTR_ERR_MEMORY;
    }

    unsigned char hash[32];
    event_sha256((unsigned char*)serialized, strlen(serialized), hash);
    memcpy(event->id, hash, NOSTR_ID_SIZE);

    free(serialized);
    return NOSTR_OK;
}

nostr_error_t nostr_event_to_json(const nostr_event* event, char** json)
{
    if (!event || !json) {
        return NOSTR_ERR_INVALID_PARAM;
    }

#ifdef NOSTR_FEATURE_JSON_ENHANCED
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return NOSTR_ERR_MEMORY;
    }

    char hex_buffer[129];  // 64 bytes * 2 + null terminator
    
    for (int i = 0; i < NOSTR_ID_SIZE; i++) {
        sprintf(hex_buffer + i * 2, "%02x", event->id[i]);
    }
    hex_buffer[64] = '\0';
    cJSON_AddStringToObject(root, "id", hex_buffer);

    for (int i = 0; i < NOSTR_PUBKEY_SIZE; i++) {
        sprintf(hex_buffer + i * 2, "%02x", event->pubkey.data[i]);
    }
    hex_buffer[64] = '\0';
    cJSON_AddStringToObject(root, "pubkey", hex_buffer);

    cJSON_AddNumberToObject(root, "created_at", event->created_at);
    cJSON_AddNumberToObject(root, "kind", event->kind);

    cJSON* tags_array = cJSON_CreateArray();
    for (size_t i = 0; i < event->tags_count; i++) {
        cJSON* tag_array = cJSON_CreateArray();
        for (size_t j = 0; j < event->tags[i].count; j++) {
            const char* tag_value = event->tags[i].values[j] ? event->tags[i].values[j] : "";
            cJSON_AddItemToArray(tag_array, cJSON_CreateString(tag_value));
        }
        cJSON_AddItemToArray(tags_array, tag_array);
    }
    cJSON_AddItemToObject(root, "tags", tags_array);

    cJSON_AddStringToObject(root, "content", event->content ? event->content : "");

    for (int i = 0; i < NOSTR_SIG_SIZE; i++) {
        sprintf(hex_buffer + i * 2, "%02x", event->sig[i]);
    }
    hex_buffer[128] = '\0';
    cJSON_AddStringToObject(root, "sig", hex_buffer);

    *json = cJSON_Print(root);
    cJSON_Delete(root);

    return *json ? NOSTR_OK : NOSTR_ERR_MEMORY;
#else
    return NOSTR_ERR_NOT_SUPPORTED;
#endif
}

static int hex_to_bytes(const char* hex, unsigned char* bytes, size_t bytes_len)
{
    if (strlen(hex) != bytes_len * 2) {
        return 0;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        if (sscanf(hex + i * 2, "%2hhx", &bytes[i]) != 1) {
            return 0;
        }
    }
    return 1;
}

nostr_error_t nostr_event_from_json(const char* json, nostr_event** event)
{
    if (!json || !event) {
        return NOSTR_ERR_INVALID_PARAM;
    }

#ifdef NOSTR_FEATURE_JSON_ENHANCED
    cJSON* root = cJSON_Parse(json);
    if (!root) {
        return NOSTR_ERR_JSON_PARSE;
    }

    *event = calloc(1, sizeof(nostr_event));
    if (!*event) {
        cJSON_Delete(root);
        return NOSTR_ERR_MEMORY;
    }
    
    if (tag_arena_create(&(*event)->tag_arena, 1024) != NOSTR_OK) {
        free(*event);
        cJSON_Delete(root);
        return NOSTR_ERR_MEMORY;
    }

    cJSON* id_json = cJSON_GetObjectItem(root, "id");
    if (id_json && cJSON_IsString(id_json)) {
        if (!hex_to_bytes(id_json->valuestring, (*event)->id, NOSTR_ID_SIZE)) {
            nostr_event_destroy(*event);
            cJSON_Delete(root);
            return NOSTR_ERR_INVALID_EVENT;
        }
    }

    cJSON* pubkey_json = cJSON_GetObjectItem(root, "pubkey");
    if (pubkey_json && cJSON_IsString(pubkey_json)) {
        if (!hex_to_bytes(pubkey_json->valuestring, (*event)->pubkey.data, NOSTR_PUBKEY_SIZE)) {
            nostr_event_destroy(*event);
            cJSON_Delete(root);
            return NOSTR_ERR_INVALID_EVENT;
        }
    }

    cJSON* created_at_json = cJSON_GetObjectItem(root, "created_at");
    if (created_at_json && cJSON_IsNumber(created_at_json)) {
        (*event)->created_at = (int64_t)created_at_json->valuedouble;
    }

    cJSON* kind_json = cJSON_GetObjectItem(root, "kind");
    if (kind_json && cJSON_IsNumber(kind_json)) {
        (*event)->kind = (uint16_t)kind_json->valueint;
    }

    cJSON* content_json = cJSON_GetObjectItem(root, "content");
    if (content_json && cJSON_IsString(content_json)) {
        (*event)->content = strdup(content_json->valuestring);
        if (!(*event)->content) {
            nostr_event_destroy(*event);
            cJSON_Delete(root);
            return NOSTR_ERR_MEMORY;
        }
    }

    cJSON* tags_json = cJSON_GetObjectItem(root, "tags");
    if (tags_json && cJSON_IsArray(tags_json)) {
        int tags_count = cJSON_GetArraySize(tags_json);
        if (tags_count > 0) {
            (*event)->tags = malloc(sizeof(nostr_tag) * tags_count);
            if (!(*event)->tags) {
                nostr_event_destroy(*event);
                cJSON_Delete(root);
                return NOSTR_ERR_MEMORY;
            }

            (*event)->tags_count = 0;
            for (int i = 0; i < tags_count; i++) {
                cJSON* tag_json = cJSON_GetArrayItem(tags_json, i);
                if (cJSON_IsArray(tag_json)) {
                    int tag_size = cJSON_GetArraySize(tag_json);
                    if (tag_size > 0) {
                        const char** temp_values = malloc(sizeof(char*) * tag_size);
                        if (!temp_values) {
                            nostr_event_destroy(*event);
                            cJSON_Delete(root);
                            return NOSTR_ERR_MEMORY;
                        }
                        
                        for (int j = 0; j < tag_size; j++) {
                            cJSON* value_json = cJSON_GetArrayItem(tag_json, j);
                            if (cJSON_IsString(value_json)) {
                                temp_values[j] = value_json->valuestring;
                            } else {
                                temp_values[j] = "";
                            }
                        }
                        
                        if (nostr_event_add_tag(*event, temp_values, tag_size) != NOSTR_OK) {
                            free(temp_values);
                            nostr_event_destroy(*event);
                            cJSON_Delete(root);
                            return NOSTR_ERR_MEMORY;
                        }
                        
                        free(temp_values);
                    }
                }
            }
        }
    }

    cJSON* sig_json = cJSON_GetObjectItem(root, "sig");
    if (sig_json && cJSON_IsString(sig_json)) {
        if (!hex_to_bytes(sig_json->valuestring, (*event)->sig, NOSTR_SIG_SIZE)) {
            nostr_event_destroy(*event);
            cJSON_Delete(root);
            return NOSTR_ERR_INVALID_EVENT;
        }
    }

    cJSON_Delete(root);
    return NOSTR_OK;
#else
    return NOSTR_ERR_NOT_SUPPORTED;
#endif
}

nostr_error_t nostr_event_sign(nostr_event* event, const nostr_privkey* privkey)
{
    if (!event || !privkey) {
        return NOSTR_ERR_INVALID_PARAM;
    }

#ifdef HAVE_NOSCRYPT
    if (!nc_ctx) {
        nostr_error_t err = nostr_init();
        if (err != NOSTR_OK) {
            return err;
        }
    }

    // Convert to noscrypt types
    NCSecretKey nc_secret;
    NCPublicKey nc_public;
    memcpy(nc_secret.key, privkey->data, NC_SEC_KEY_SIZE);

    // Get public key using noscrypt
    if (NCGetPublicKey(nc_ctx, &nc_secret, &nc_public) != NC_SUCCESS) {
        memset(&nc_secret, 0, sizeof(nc_secret));
        return NOSTR_ERR_INVALID_KEY;
    }

    // Copy public key to event
    memcpy(event->pubkey.data, nc_public.key, NOSTR_PUBKEY_SIZE);

    // Compute event ID with the public key set
    nostr_error_t result = nostr_event_compute_id(event);
    if (result != NOSTR_OK) {
        memset(&nc_secret, 0, sizeof(nc_secret));
        return result;
    }

    // Sign the event ID using noscrypt
    // Generate secure random for signature
    uint8_t random32[32];
    if (nostr_random_bytes(random32, 32) != 1) {
        memset(&nc_secret, 0, sizeof(nc_secret));
        return NOSTR_ERR_MEMORY;
    }
    
    if (NCSignData(nc_ctx, &nc_secret, random32, event->id, NOSTR_ID_SIZE, event->sig) != NC_SUCCESS) {
        memset(&nc_secret, 0, sizeof(nc_secret));
        return NOSTR_ERR_INVALID_SIGNATURE;
    }

    // Clear sensitive data
    memset(&nc_secret, 0, sizeof(nc_secret));

#elif defined(HAVE_SECP256K1)
    if (!secp256k1_ctx) {
        nostr_error_t err = nostr_init();
        if (err != NOSTR_OK) {
            return err;
        }
    }

    // Create keypair from private key
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(secp256k1_ctx, &keypair, privkey->data)) {
        return NOSTR_ERR_INVALID_KEY;
    }

    // Extract x-only public key from keypair
    secp256k1_xonly_pubkey xonly_pubkey;
    if (!secp256k1_keypair_xonly_pub(secp256k1_ctx, &xonly_pubkey, NULL, &keypair)) {
        return NOSTR_ERR_INVALID_KEY;
    }

    // Serialize x-only pubkey
    if (!secp256k1_xonly_pubkey_serialize(secp256k1_ctx, event->pubkey.data, &xonly_pubkey)) {
        return NOSTR_ERR_INVALID_KEY;
    }

    // Compute event ID with the public key set
    nostr_error_t result = nostr_event_compute_id(event);
    if (result != NOSTR_OK) {
        return result;
    }

    // Generate auxiliary randomness for BIP-340
    unsigned char aux_rand[32];
    if (nostr_random_bytes(aux_rand, 32) != 1) {
        return NOSTR_ERR_MEMORY;
    }

    // Sign the event ID using Schnorr signatures (BIP-340)
    if (!secp256k1_schnorrsig_sign32(secp256k1_ctx, event->sig, event->id, &keypair, aux_rand)) {
        return NOSTR_ERR_INVALID_SIGNATURE;
    }

    // Clear sensitive data
    memset(aux_rand, 0, sizeof(aux_rand));
    memset(&keypair, 0, sizeof(keypair));
#else
    // No crypto backend available
    return NOSTR_ERR_NOT_SUPPORTED;
#endif

    return NOSTR_OK;
}

nostr_error_t nostr_event_verify(const nostr_event* event)
{
    if (!event) {
        return NOSTR_ERR_INVALID_PARAM;
    }

#ifdef HAVE_NOSCRYPT
    if (!nc_ctx) {
        nostr_error_t err = nostr_init();
        if (err != NOSTR_OK) {
            return err;
        }
    }

    // First verify the event ID matches the content
    nostr_event temp_event = *event;
    
    // Save original ID
    unsigned char original_id[NOSTR_ID_SIZE];
    memcpy(original_id, event->id, NOSTR_ID_SIZE);
    
    // Recompute ID on the copy
    nostr_error_t result = nostr_event_compute_id(&temp_event);
    if (result != NOSTR_OK) {
        return result;
    }

    // Compare with original
    if (nostr_constant_time_memcmp(original_id, temp_event.id, NOSTR_ID_SIZE) != 0) {
        return NOSTR_ERR_INVALID_EVENT;
    }

    // Convert to noscrypt types
    NCPublicKey nc_public;
    memcpy(nc_public.key, event->pubkey.data, NC_PUBKEY_SIZE);

    // Verify the signature using noscrypt
    if (NCVerifyData(nc_ctx, &nc_public, event->id, NOSTR_ID_SIZE, event->sig) != NC_SUCCESS) {
        return NOSTR_ERR_INVALID_SIGNATURE;
    }

#elif defined(HAVE_SECP256K1)
    if (!secp256k1_ctx) {
        nostr_error_t err = nostr_init();
        if (err != NOSTR_OK) {
            return err;
        }
    }

    // First verify the event ID matches the content
    nostr_event temp_event = *event;
    
    // Save original ID
    unsigned char original_id[NOSTR_ID_SIZE];
    memcpy(original_id, event->id, NOSTR_ID_SIZE);
    
    // Recompute ID on the copy
    nostr_error_t result = nostr_event_compute_id(&temp_event);
    if (result != NOSTR_OK) {
        return result;
    }

    // Compare with original
    if (nostr_constant_time_memcmp(original_id, temp_event.id, NOSTR_ID_SIZE) != 0) {
        return NOSTR_ERR_INVALID_EVENT;
    }

    // Parse the x-only public key
    secp256k1_xonly_pubkey xonly_pubkey;
    if (!secp256k1_xonly_pubkey_parse(secp256k1_ctx, &xonly_pubkey, event->pubkey.data)) {
        return NOSTR_ERR_INVALID_KEY;
    }

    // Verify the Schnorr signature
    int is_valid = secp256k1_schnorrsig_verify(secp256k1_ctx, event->sig, event->id, 32, &xonly_pubkey);
    
    if (!is_valid) {
        return NOSTR_ERR_INVALID_SIGNATURE;
    }
#else
    // No crypto backend available - can't verify signatures
    return NOSTR_ERR_NOT_SUPPORTED;
#endif
    
    return NOSTR_OK;
}