#include "nostr.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#ifdef NOSTR_FEATURE_THREADING
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif
#endif

static nostr_config g_config;
static int g_config_initialized = 0;
static nostr_config_callback g_config_callback = NULL;
static void* g_config_callback_user_data = NULL;
#ifdef NOSTR_FEATURE_THREADING
#ifdef _WIN32
static CRITICAL_SECTION config_lock;
static INIT_ONCE config_init_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK config_init_lock_callback(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context) {
    (void)InitOnce;
    (void)Parameter;
    (void)Context;
    InitializeCriticalSection(&config_lock);
    return TRUE;
}
#else
static pthread_mutex_t config_lock = PTHREAD_MUTEX_INITIALIZER;
#endif
#endif

static void lock_config(void) {
#ifdef NOSTR_FEATURE_THREADING
#ifdef _WIN32
    InitOnceExecuteOnce(&config_init_once, config_init_lock_callback, NULL, NULL);
    EnterCriticalSection(&config_lock);
#else
    pthread_mutex_lock(&config_lock);
#endif
#endif
}

static void unlock_config(void) {
#ifdef NOSTR_FEATURE_THREADING
#ifdef _WIN32
    LeaveCriticalSection(&config_lock);
#else
    pthread_mutex_unlock(&config_lock);
#endif
#endif
}

nostr_error_t nostr_config_get_defaults(nostr_config* config) {
    if (!config) return NOSTR_ERR_INVALID_PARAM;
    
    config->nip44_min_plaintext_size = 1;
    config->nip44_max_plaintext_size = 65535;
    config->max_sessions = 100;
    config->session_timeout_secs = 3600;
    config->max_permissions = 32;
    config->max_content_size = 65536;
    config->max_tags = 100;
    config->max_tag_values = 50;
    config->relay_connect_timeout_ms = 30000;
    config->relay_response_timeout_ms = 10000;
    config->encryption_default_nip = 44;
    config->secure_memory_lock = 0;
    config->debug_mode = 0;
    
    return NOSTR_OK;
}

static uint32_t parse_uint32_env(const char* name, uint32_t default_val) {
    const char* env = getenv(name);
    if (!env) return default_val;
    
    char* endptr;
    unsigned long val = strtoul(env, &endptr, 10);
    if (*endptr != '\0' || val > UINT32_MAX) return default_val;
    
    return (uint32_t)val;
}

static int parse_int_env(const char* name, int default_val) {
    const char* env = getenv(name);
    if (!env) return default_val;
    
    char* endptr;
    long val = strtol(env, &endptr, 10);
    if (*endptr != '\0' || val > INT_MAX || val < INT_MIN) return default_val;
    
    return (int)val;
}

nostr_error_t nostr_config_load_env(nostr_config* config) {
    if (!config) return NOSTR_ERR_INVALID_PARAM;
    
    config->nip44_min_plaintext_size = parse_uint32_env("NOSTR_NIP44_MIN_SIZE", config->nip44_min_plaintext_size);
    config->nip44_max_plaintext_size = parse_uint32_env("NOSTR_NIP44_MAX_SIZE", config->nip44_max_plaintext_size);
    config->max_sessions = parse_uint32_env("NOSTR_MAX_SESSIONS", config->max_sessions);
    config->session_timeout_secs = parse_uint32_env("NOSTR_SESSION_TIMEOUT", config->session_timeout_secs);
    config->max_permissions = parse_uint32_env("NOSTR_MAX_PERMISSIONS", config->max_permissions);
    config->max_content_size = parse_uint32_env("NOSTR_MAX_CONTENT_SIZE", config->max_content_size);
    config->max_tags = parse_uint32_env("NOSTR_MAX_TAGS", config->max_tags);
    config->max_tag_values = parse_uint32_env("NOSTR_MAX_TAG_VALUES", config->max_tag_values);
    config->relay_connect_timeout_ms = parse_uint32_env("NOSTR_RELAY_CONNECT_TIMEOUT", config->relay_connect_timeout_ms);
    config->relay_response_timeout_ms = parse_uint32_env("NOSTR_RELAY_RESPONSE_TIMEOUT", config->relay_response_timeout_ms);
    config->encryption_default_nip = parse_int_env("NOSTR_ENCRYPTION_DEFAULT", config->encryption_default_nip);
    config->secure_memory_lock = parse_int_env("NOSTR_SECURE_MEMORY_LOCK", config->secure_memory_lock);
    config->debug_mode = parse_int_env("NOSTR_DEBUG", config->debug_mode);
    
    return NOSTR_OK;
}

nostr_error_t nostr_config_validate(const nostr_config* config) {
    if (!config) return NOSTR_ERR_INVALID_PARAM;
    
    if (config->nip44_min_plaintext_size < 1 || config->nip44_min_plaintext_size > 65535) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (config->nip44_max_plaintext_size < config->nip44_min_plaintext_size || 
        config->nip44_max_plaintext_size > 65535) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (config->max_sessions == 0 || config->max_sessions > 10000) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (config->session_timeout_secs < 60 || config->session_timeout_secs > 86400) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (config->max_permissions == 0 || config->max_permissions > 1000) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (config->max_content_size < 1024 || config->max_content_size > 1048576) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (config->max_tags == 0 || config->max_tags > 1000) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (config->max_tag_values == 0 || config->max_tag_values > 1000) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (config->relay_connect_timeout_ms < 1000 || config->relay_connect_timeout_ms > 300000) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (config->relay_response_timeout_ms < 1000 || config->relay_response_timeout_ms > 60000) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (config->encryption_default_nip != 4 && config->encryption_default_nip != 44) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (config->secure_memory_lock < 0 || config->secure_memory_lock > 1) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (config->debug_mode < 0 || config->debug_mode > 1) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    return NOSTR_OK;
}

const nostr_config* nostr_config_get_current(void) {
    lock_config();
    if (!g_config_initialized) {
        unlock_config();
        return NULL;
    }
#ifdef _WIN32
    static __declspec(thread) nostr_config config_copy;
#else
    static __thread nostr_config config_copy;
#endif
    config_copy = g_config;
    unlock_config();
    return &config_copy;
}

nostr_error_t nostr_init_with_config(const nostr_config* config) {
    lock_config();
    
    if (g_config_initialized) {
        unlock_config();
        return NOSTR_OK;
    }
    
    nostr_error_t err;
    
    if (config) {
        err = nostr_config_validate(config);
        if (err != NOSTR_OK) {
            unlock_config();
            return err;
        }
        g_config = *config;
    } else {
        err = nostr_config_get_defaults(&g_config);
        if (err != NOSTR_OK) {
            unlock_config();
            return err;
        }
        err = nostr_config_load_env(&g_config);
        if (err != NOSTR_OK) {
            unlock_config();
            return err;
        }
        err = nostr_config_validate(&g_config);
        if (err != NOSTR_OK) {
            unlock_config();
            return err;
        }
    }
    
    g_config_initialized = 1;
    unlock_config();
    return nostr_init();
}

nostr_error_t nostr_config_set_callback(nostr_config_callback callback, void* user_data) {
    lock_config();
    g_config_callback = callback;
    g_config_callback_user_data = user_data;
    unlock_config();
    return NOSTR_OK;
}

nostr_error_t nostr_config_update(const nostr_config* config) {
    if (!config) return NOSTR_ERR_INVALID_PARAM;
    
    lock_config();
    
    if (!g_config_initialized) {
        unlock_config();
        return NOSTR_ERR_NOT_FOUND;
    }
    
    nostr_error_t err = nostr_config_validate(config);
    if (err != NOSTR_OK) {
        unlock_config();
        return err;
    }
    
    nostr_config old_config = g_config;
    g_config = *config;
    
    if (g_config_callback) {
        g_config_callback(&old_config, &g_config, g_config_callback_user_data);
    }
    
    unlock_config();
    return NOSTR_OK;
}