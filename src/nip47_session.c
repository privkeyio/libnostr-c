#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <openssl/rand.h>
#include "../include/nostr.h"


typedef struct {
    char* name;
    uint64_t limit_msats;
    time_t reset_time;
    uint64_t used_msats;
} permission_t;

typedef struct {
    char session_id[65];
    struct nwc_connection* connection;
    permission_t* permissions;
    size_t permission_count;
    time_t created_at;
    time_t last_used;
    time_t expires_at;
    int active;
    pthread_mutex_t lock;
} nwc_session_t;

static nwc_session_t* sessions = NULL;
static size_t max_sessions = 0;
static pthread_mutex_t sessions_lock = PTHREAD_MUTEX_INITIALIZER;
static int sessions_initialized = 0;

static void generate_session_id(char* id)
{
    uint8_t random[32];
    if (RAND_bytes(random, 32) != 1) {
        memset(random, 0, 32);
    }
    
    for (int i = 0; i < 32; i++) {
        sprintf(id + i*2, "%02x", random[i]);
    }
    id[64] = 0;
}

static void cleanup_expired_sessions()
{
    time_t now = time(NULL);
    
    for (size_t i = 0; i < max_sessions; i++) {
        if (sessions[i].active && sessions[i].expires_at < now) {
            pthread_mutex_lock(&sessions[i].lock);
            sessions[i].active = 0;
            if (sessions[i].connection) {
                nostr_nip47_free_connection(sessions[i].connection);
                sessions[i].connection = NULL;
            }
            for (size_t j = 0; j < sessions[i].permission_count; j++) {
                free(sessions[i].permissions[j].name);
            }
            sessions[i].permission_count = 0;
            pthread_mutex_unlock(&sessions[i].lock);
        }
    }
}

nostr_error_t nostr_nip47_session_init()
{
    pthread_mutex_lock(&sessions_lock);
    
    if (!sessions_initialized) {
        const nostr_config* config = nostr_config_get_current();
        max_sessions = config ? config->max_sessions : 100;
        
        sessions = calloc(max_sessions, sizeof(nwc_session_t));
        if (!sessions) {
            pthread_mutex_unlock(&sessions_lock);
            return NOSTR_ERR_MEMORY;
        }
        
        for (size_t i = 0; i < max_sessions; i++) {
            sessions[i].active = 0;
            sessions[i].permission_count = 0;
            sessions[i].connection = NULL;
            sessions[i].permissions = NULL;
            memset(sessions[i].session_id, 0, sizeof(sessions[i].session_id));
            pthread_mutex_init(&sessions[i].lock, NULL);
        }
        sessions_initialized = 1;
    }
    
    pthread_mutex_unlock(&sessions_lock);
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_session_create(const char* connection_uri, char** session_id)
{
    if (!connection_uri || !session_id) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (!sessions_initialized) {
        nostr_nip47_session_init();
    }
    
    struct nwc_connection* conn = NULL;
    nostr_error_t err = nostr_nip47_parse_connection_uri(connection_uri, &conn);
    if (err != NOSTR_OK) {
        return err;
    }
    
    pthread_mutex_lock(&sessions_lock);
    cleanup_expired_sessions();
    
    int slot = -1;
    for (size_t i = 0; i < max_sessions; i++) {
        if (!sessions[i].active) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        pthread_mutex_unlock(&sessions_lock);
        nostr_nip47_free_connection(conn);
        return NOSTR_ERR_MEMORY;
    }
    
    nwc_session_t* session = &sessions[slot];
    pthread_mutex_lock(&session->lock);
    
    generate_session_id(session->session_id);
    session->connection = conn;
    session->created_at = time(NULL);
    session->last_used = session->created_at;
    const nostr_config* config = nostr_config_get_current();
    uint32_t timeout = config ? config->session_timeout_secs : 3600;
    session->expires_at = session->created_at + timeout;
    session->active = 1;
    session->permission_count = 0;
    
    *session_id = strdup(session->session_id);
    
    pthread_mutex_unlock(&session->lock);
    pthread_mutex_unlock(&sessions_lock);
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_session_add_permission(const char* session_id, const char* permission,
                                                 uint64_t limit_msats, uint32_t reset_interval_secs)
{
    if (!session_id || !permission) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&sessions_lock);
    
    nwc_session_t* session = NULL;
    for (size_t i = 0; i < max_sessions; i++) {
        if (sessions[i].active && strcmp(sessions[i].session_id, session_id) == 0) {
            session = &sessions[i];
            break;
        }
    }
    
    if (!session) {
        pthread_mutex_unlock(&sessions_lock);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&session->lock);
    pthread_mutex_unlock(&sessions_lock);
    
    const nostr_config* config = nostr_config_get_current();
    uint32_t max_perms = config ? config->max_permissions : 32;
    
    if (session->permission_count >= max_perms) {
        pthread_mutex_unlock(&session->lock);
        return NOSTR_ERR_MEMORY;
    }
    
    if (session->permissions == NULL) {
        session->permissions = calloc(max_perms, sizeof(permission_t));
        if (!session->permissions) {
            pthread_mutex_unlock(&session->lock);
            return NOSTR_ERR_MEMORY;
        }
    }
    
    permission_t* perm = &session->permissions[session->permission_count];
    perm->name = strdup(permission);
    perm->limit_msats = limit_msats;
    perm->reset_time = time(NULL) + reset_interval_secs;
    perm->used_msats = 0;
    
    session->permission_count++;
    
    pthread_mutex_unlock(&session->lock);
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_session_check_permission(const char* session_id, const char* method,
                                                   uint64_t amount_msats)
{
    if (!session_id || !method) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&sessions_lock);
    
    nwc_session_t* session = NULL;
    for (size_t i = 0; i < max_sessions; i++) {
        if (sessions[i].active && strcmp(sessions[i].session_id, session_id) == 0) {
            session = &sessions[i];
            break;
        }
    }
    
    if (!session) {
        pthread_mutex_unlock(&sessions_lock);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&session->lock);
    pthread_mutex_unlock(&sessions_lock);
    
    time_t now = time(NULL);
    if (session->expires_at < now) {
        pthread_mutex_unlock(&session->lock);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    session->last_used = now;
    
    permission_t* perm = NULL;
    for (size_t i = 0; i < session->permission_count; i++) {
        if (strcmp(session->permissions[i].name, method) == 0 ||
            strcmp(session->permissions[i].name, "*") == 0) {
            perm = &session->permissions[i];
            break;
        }
    }
    
    if (!perm) {
        pthread_mutex_unlock(&session->lock);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (perm->reset_time < now) {
        perm->used_msats = 0;
        perm->reset_time = now + (perm->reset_time - (now - perm->reset_time));
    }
    
    if (perm->limit_msats > 0 && perm->used_msats + amount_msats > perm->limit_msats) {
        pthread_mutex_unlock(&session->lock);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    perm->used_msats += amount_msats;
    
    pthread_mutex_unlock(&session->lock);
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_session_get_connection(const char* session_id, struct nwc_connection** connection)
{
    if (!session_id || !connection) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&sessions_lock);
    
    nwc_session_t* session = NULL;
    for (size_t i = 0; i < max_sessions; i++) {
        if (sessions[i].active && strcmp(sessions[i].session_id, session_id) == 0) {
            session = &sessions[i];
            break;
        }
    }
    
    if (!session) {
        pthread_mutex_unlock(&sessions_lock);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&session->lock);
    pthread_mutex_unlock(&sessions_lock);
    
    time_t now = time(NULL);
    if (session->expires_at < now) {
        pthread_mutex_unlock(&session->lock);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    session->last_used = now;
    *connection = session->connection;
    
    pthread_mutex_unlock(&session->lock);
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_session_extend(const char* session_id, uint32_t additional_secs)
{
    if (!session_id) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&sessions_lock);
    
    nwc_session_t* session = NULL;
    for (size_t i = 0; i < max_sessions; i++) {
        if (sessions[i].active && strcmp(sessions[i].session_id, session_id) == 0) {
            session = &sessions[i];
            break;
        }
    }
    
    if (!session) {
        pthread_mutex_unlock(&sessions_lock);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&session->lock);
    pthread_mutex_unlock(&sessions_lock);
    
    session->expires_at += additional_secs;
    
    pthread_mutex_unlock(&session->lock);
    return NOSTR_OK;
}

nostr_error_t nostr_nip47_session_destroy(const char* session_id)
{
    if (!session_id) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&sessions_lock);
    
    nwc_session_t* session = NULL;
    for (size_t i = 0; i < max_sessions; i++) {
        if (sessions[i].active && strcmp(sessions[i].session_id, session_id) == 0) {
            session = &sessions[i];
            break;
        }
    }
    
    if (!session) {
        pthread_mutex_unlock(&sessions_lock);
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&session->lock);
    pthread_mutex_unlock(&sessions_lock);
    
    session->active = 0;
    if (session->connection) {
        nostr_nip47_free_connection(session->connection);
        session->connection = NULL;
    }
    
    for (size_t i = 0; i < session->permission_count; i++) {
        free(session->permissions[i].name);
    }
    free(session->permissions);
    session->permissions = NULL;
    session->permission_count = 0;
    
    pthread_mutex_unlock(&session->lock);
    return NOSTR_OK;
}