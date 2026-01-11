#include "nostr.h"

#ifdef NOSTR_FEATURE_NIP13

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#ifdef NOSTR_FEATURE_THREADING
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif
#endif
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#ifdef NOSTR_FEATURE_JSON_ENHANCED
#include <cjson/cJSON.h>
#endif

static int zero_bits(unsigned char b)
{
    int n = 0;

    if (b == 0)
        return 8;

    while (b >>= 1)
        n++;

    return 7-n;
}

int nostr_nip13_calculate_difficulty(const uint8_t* event_id)
{
    if (!event_id) {
        return 0;
    }
    
    int bits, total, i;
    for (i = 0, total = 0; i < 32; i++) {
        bits = zero_bits(event_id[i]);
        total += bits;
        if (bits != 8)
            break;
    }
    return total;
}

static nostr_error_t find_nonce_tag_index(const nostr_event* event, size_t* index)
{
    if (!event || !index) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    for (size_t i = 0; i < event->tags_count; i++) {
        if (event->tags[i].count > 0 && event->tags[i].values[0] && 
            strcmp(event->tags[i].values[0], "nonce") == 0) {
            *index = i;
            return NOSTR_OK;
        }
    }
    
    return NOSTR_ERR_NOT_FOUND;
}

nostr_error_t nostr_nip13_add_nonce_tag(nostr_event* event, uint64_t nonce_value, int target_difficulty)
{
    if (!event) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    char nonce_str[32];
    snprintf(nonce_str, sizeof(nonce_str), "%" PRIu64, nonce_value);
    
    char target_str[16] = {0};
    if (target_difficulty > 0) {
        snprintf(target_str, sizeof(target_str), "%d", target_difficulty);
    }
    
    const char* tag_values[3] = {"nonce", nonce_str, NULL};
    size_t count = 2;
    
    if (target_difficulty > 0) {
        tag_values[2] = target_str;
        count = 3;
    }
    
    size_t nonce_idx;
    nostr_error_t err = find_nonce_tag_index(event, &nonce_idx);
    
    if (err == NOSTR_OK) {
        if (event->tags[nonce_idx].count >= 2 && event->tags[nonce_idx].values[1]) {
            free(event->tags[nonce_idx].values[1]);
        }
        if (event->tags[nonce_idx].count >= 3 && event->tags[nonce_idx].values[2]) {
            free(event->tags[nonce_idx].values[2]);
            event->tags[nonce_idx].values[2] = NULL;
        }
        
        event->tags[nonce_idx].values[1] = strdup(nonce_str);
        if (!event->tags[nonce_idx].values[1]) {
            return NOSTR_ERR_MEMORY;
        }
        
        if (target_difficulty > 0) {
            if (event->tags[nonce_idx].count < 3) {
                char** new_values = realloc(event->tags[nonce_idx].values, 3 * sizeof(char*));
                if (!new_values) {
                    return NOSTR_ERR_MEMORY;
                }
                event->tags[nonce_idx].values = new_values;
                event->tags[nonce_idx].values[2] = NULL;
                event->tags[nonce_idx].count = 3;
            }
            
            event->tags[nonce_idx].values[2] = strdup(target_str);
            if (!event->tags[nonce_idx].values[2]) {
                return NOSTR_ERR_MEMORY;
            }
        } else {
            event->tags[nonce_idx].count = 2;
        }
    } else {
        err = nostr_event_add_tag(event, tag_values, count);
        if (err != NOSTR_OK) {
            return err;
        }
    }
    
    return NOSTR_OK;
}

nostr_error_t nostr_nip13_mine_event(nostr_event* event, int target_difficulty, uint64_t max_iterations)
{
    if (!event || target_difficulty < 1) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    size_t nonce_idx;
    nostr_error_t err = find_nonce_tag_index(event, &nonce_idx);
    if (err != NOSTR_OK) {
        err = nostr_nip13_add_nonce_tag(event, 0, target_difficulty);
        if (err != NOSTR_OK) {
            return err;
        }
        err = find_nonce_tag_index(event, &nonce_idx);
        if (err != NOSTR_OK) {
            return err;
        }
    }
    
    uint64_t nonce = 0;
    uint64_t iterations = 0;
    
    while (max_iterations == 0 || iterations < max_iterations) {
        err = nostr_nip13_add_nonce_tag(event, nonce, target_difficulty);
        if (err != NOSTR_OK) {
            return err;
        }
        
        event->created_at = time(NULL);
        
        err = nostr_event_compute_id(event);
        if (err != NOSTR_OK) {
            return err;
        }
        
        int difficulty = nostr_nip13_calculate_difficulty(event->id);
        if (difficulty >= target_difficulty) {
            return NOSTR_OK;
        }
        
        nonce++;
        iterations++;
    }
    
    return NOSTR_ERR_NOT_FOUND;
}

nostr_error_t nostr_nip13_verify_pow(const nostr_event* event, int min_difficulty)
{
    if (!event || min_difficulty < 1) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    size_t nonce_idx;
    nostr_error_t err = find_nonce_tag_index(event, &nonce_idx);
    if (err != NOSTR_OK) {
        return NOSTR_ERR_INVALID_EVENT;
    }
    
    if (event->tags[nonce_idx].count < 2 || !event->tags[nonce_idx].values[1]) {
        return NOSTR_ERR_INVALID_EVENT;
    }
    
    int difficulty = nostr_nip13_calculate_difficulty(event->id);
    if (difficulty < min_difficulty) {
        return NOSTR_ERR_INVALID_EVENT;
    }
    
    if (event->tags[nonce_idx].count >= 3 && event->tags[nonce_idx].values[2]) {
        int committed_difficulty = atoi(event->tags[nonce_idx].values[2]);
        if (committed_difficulty > 0 && difficulty < committed_difficulty) {
            return NOSTR_ERR_INVALID_EVENT;
        }
    }
    
    return NOSTR_OK;
}

#ifdef NOSTR_FEATURE_THREADING

#ifdef _WIN32
typedef struct {
    nostr_event* event;
    int target_difficulty;
    uint64_t start_nonce;
    uint64_t max_iterations;
    int found;
    uint64_t result_nonce;
    CRITICAL_SECTION* mutex;
    int* global_found;
} mining_thread_data;

static DWORD WINAPI mining_thread(LPVOID arg)
{
    mining_thread_data* data = (mining_thread_data*)arg;
    uint64_t nonce = data->start_nonce;
    uint64_t iterations = 0;
    
    while (!*(data->global_found) && 
           (data->max_iterations == 0 || iterations < data->max_iterations)) {
        
        EnterCriticalSection(data->mutex);
        if (*(data->global_found)) {
            LeaveCriticalSection(data->mutex);
            break;
        }
        
        nostr_error_t err = nostr_nip13_add_nonce_tag(data->event, nonce, data->target_difficulty);
        if (err != NOSTR_OK) {
            LeaveCriticalSection(data->mutex);
            break;
        }
        
        data->event->created_at = time(NULL);
        
        err = nostr_event_compute_id(data->event);
        if (err != NOSTR_OK) {
            LeaveCriticalSection(data->mutex);
            break;
        }
        
        int difficulty = nostr_nip13_calculate_difficulty(data->event->id);
        if (difficulty >= data->target_difficulty) {
            *(data->global_found) = 1;
            data->found = 1;
            data->result_nonce = nonce;
            LeaveCriticalSection(data->mutex);
            break;
        }
        
        LeaveCriticalSection(data->mutex);
        
        nonce += 1000;
        iterations++;
        
        if (iterations % 1000 == 0) {
            Sleep(1);
        }
    }
    
    return 0;
}
#else
typedef struct {
    nostr_event* event;
    int target_difficulty;
    uint64_t start_nonce;
    uint64_t max_iterations;
    int found;
    uint64_t result_nonce;
    pthread_mutex_t* mutex;
    int* global_found;
} mining_thread_data;

static void* mining_thread(void* arg)
{
    mining_thread_data* data = (mining_thread_data*)arg;
    uint64_t nonce = data->start_nonce;
    uint64_t iterations = 0;
    
    while (!*(data->global_found) && 
           (data->max_iterations == 0 || iterations < data->max_iterations)) {
        
        pthread_mutex_lock(data->mutex);
        if (*(data->global_found)) {
            pthread_mutex_unlock(data->mutex);
            break;
        }
        
        nostr_error_t err = nostr_nip13_add_nonce_tag(data->event, nonce, data->target_difficulty);
        if (err != NOSTR_OK) {
            pthread_mutex_unlock(data->mutex);
            break;
        }
        
        data->event->created_at = time(NULL);
        
        err = nostr_event_compute_id(data->event);
        if (err != NOSTR_OK) {
            pthread_mutex_unlock(data->mutex);
            break;
        }
        
        int difficulty = nostr_nip13_calculate_difficulty(data->event->id);
        if (difficulty >= data->target_difficulty) {
            *(data->global_found) = 1;
            data->found = 1;
            data->result_nonce = nonce;
            pthread_mutex_unlock(data->mutex);
            break;
        }
        
        pthread_mutex_unlock(data->mutex);
        
        nonce += 1000;
        iterations++;
        
        if (iterations % 1000 == 0) {
            usleep(1000);
        }
    }
    
    return NULL;
}
#endif

nostr_error_t nostr_nip13_mine_event_threaded(nostr_event* event, int target_difficulty, 
                                              int num_threads, uint64_t max_iterations)
{
    if (!event || target_difficulty < 1) {
        return NOSTR_ERR_INVALID_PARAM;
    }
    
    if (num_threads <= 0) {
#ifdef _WIN32
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        num_threads = sysinfo.dwNumberOfProcessors;
#else
        num_threads = sysconf(_SC_NPROCESSORS_ONLN);
#endif
        if (num_threads <= 0) {
            num_threads = 4;
        }
    }
    
    size_t nonce_idx;
    nostr_error_t err = find_nonce_tag_index(event, &nonce_idx);
    if (err != NOSTR_OK) {
        err = nostr_nip13_add_nonce_tag(event, 0, target_difficulty);
        if (err != NOSTR_OK) {
            return err;
        }
    }

#ifdef _WIN32
    HANDLE* threads = malloc(num_threads * sizeof(HANDLE));
    mining_thread_data* thread_data = malloc(num_threads * sizeof(mining_thread_data));
    if (!threads || !thread_data) {
        free(threads);
        free(thread_data);
        return NOSTR_ERR_MEMORY;
    }
    
    CRITICAL_SECTION mutex;
    InitializeCriticalSection(&mutex);
    int global_found = 0;
    
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].event = event;
        thread_data[i].target_difficulty = target_difficulty;
        thread_data[i].start_nonce = i;
        thread_data[i].max_iterations = max_iterations;
        thread_data[i].found = 0;
        thread_data[i].result_nonce = 0;
        thread_data[i].mutex = &mutex;
        thread_data[i].global_found = &global_found;
        
        threads[i] = CreateThread(NULL, 0, mining_thread, &thread_data[i], 0, NULL);
        if (threads[i] == NULL) {
            global_found = 1;
            for (int j = 0; j < i; j++) {
                if (threads[j] != NULL) {
                    WaitForSingleObject(threads[j], INFINITE);
                    CloseHandle(threads[j]);
                }
            }
            DeleteCriticalSection(&mutex);
            free(threads);
            free(thread_data);
            return NOSTR_ERR_PROTOCOL;
        }
    }
    
    for (int i = 0; i < num_threads; i++) {
        if (threads[i] != NULL) {
            WaitForSingleObject(threads[i], INFINITE);
            CloseHandle(threads[i]);
        }
    }
    
    nostr_error_t result = NOSTR_ERR_NOT_FOUND;
    for (int i = 0; i < num_threads; i++) {
        if (thread_data[i].found) {
            result = NOSTR_OK;
            break;
        }
    }
    
    DeleteCriticalSection(&mutex);
    free(threads);
    free(thread_data);
#else
    pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
    mining_thread_data* thread_data = malloc(num_threads * sizeof(mining_thread_data));
    if (!threads || !thread_data) {
        free(threads);
        free(thread_data);
        return NOSTR_ERR_MEMORY;
    }
    
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    int global_found = 0;
    
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].event = event;
        thread_data[i].target_difficulty = target_difficulty;
        thread_data[i].start_nonce = i;
        thread_data[i].max_iterations = max_iterations;
        thread_data[i].found = 0;
        thread_data[i].result_nonce = 0;
        thread_data[i].mutex = &mutex;
        thread_data[i].global_found = &global_found;
        
        if (pthread_create(&threads[i], NULL, mining_thread, &thread_data[i]) != 0) {
            global_found = 1;
            for (int j = 0; j < i; j++) {
                pthread_join(threads[j], NULL);
            }
            free(threads);
            free(thread_data);
            return NOSTR_ERR_PROTOCOL;
        }
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    nostr_error_t result = NOSTR_ERR_NOT_FOUND;
    for (int i = 0; i < num_threads; i++) {
        if (thread_data[i].found) {
            result = NOSTR_OK;
            break;
        }
    }
    
    pthread_mutex_destroy(&mutex);
    free(threads);
    free(thread_data);
#endif
    
    return result;
}

#else

/* Threading disabled - provide fallback non-threaded implementation */
nostr_error_t nostr_nip13_mine_event_threaded(nostr_event* event, int target_difficulty, 
                                              int num_threads, uint64_t max_iterations)
{
    (void)num_threads; /* unused when threading disabled */
    return nostr_nip13_mine_event(event, target_difficulty, max_iterations);
}

#endif /* NOSTR_FEATURE_THREADING */

#else

/* NIP-13 functionality not available */
int nostr_nip13_calculate_difficulty(const uint8_t* event_id) {
    (void)event_id;
    return -1;
}

nostr_error_t nostr_nip13_mine_event(nostr_event* event, int target_difficulty, uint64_t max_iterations) {
    (void)event; (void)target_difficulty; (void)max_iterations;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nip13_verify_pow(const nostr_event* event, int min_difficulty) {
    (void)event; (void)min_difficulty;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nip13_add_nonce_tag(nostr_event* event, uint64_t nonce_value, int target_difficulty) {
    (void)event; (void)nonce_value; (void)target_difficulty;
    return NOSTR_ERR_NOT_SUPPORTED;
}

nostr_error_t nostr_nip13_mine_event_threaded(nostr_event* event, int target_difficulty, int num_threads, uint64_t max_iterations) {
    (void)event; (void)target_difficulty; (void)num_threads; (void)max_iterations;
    return NOSTR_ERR_NOT_SUPPORTED;
}

#endif /* NOSTR_FEATURE_NIP13 */
