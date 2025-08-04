#include "unity.h"
#include "../include/nostr.h"
#include <pthread.h>
#include <unistd.h>

#define NUM_THREADS 10
#define ITERATIONS_PER_THREAD 100

typedef struct {
    int thread_id;
    int iterations;
    int success_count;
    nostr_error_t last_error;
} thread_data_t;

static void* test_init_thread(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    
    for (int i = 0; i < data->iterations; i++) {
        data->last_error = nostr_init();
        if (data->last_error == NOSTR_OK) {
            data->success_count++;
        }
        usleep(1000);
    }
    
    return NULL;
}

static void* test_config_thread(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    
    for (int i = 0; i < data->iterations; i++) {
        nostr_config config;
        data->last_error = nostr_config_get_defaults(&config);
        if (data->last_error == NOSTR_OK) {
            data->last_error = nostr_init_with_config(&config);
            if (data->last_error == NOSTR_OK) {
                data->success_count++;
            }
        }
        usleep(1000);
    }
    
    return NULL;
}

static void* test_key_generation_thread(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    
    for (int i = 0; i < data->iterations; i++) {
        nostr_privkey privkey;
        nostr_key pubkey;
        
        data->last_error = nostr_key_generate(&privkey, &pubkey);
        if (data->last_error == NOSTR_OK) {
            data->success_count++;
        }
        usleep(1000);
    }
    
    return NULL;
}

void test_concurrent_initialization(void) {
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].iterations = ITERATIONS_PER_THREAD;
        thread_data[i].success_count = 0;
        thread_data[i].last_error = NOSTR_OK;
        
        int result = pthread_create(&threads[i], NULL, test_init_thread, &thread_data[i]);
        TEST_ASSERT_EQUAL(0, result);
    }
    
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        TEST_ASSERT_EQUAL(NOSTR_OK, thread_data[i].last_error);
        TEST_ASSERT_EQUAL(ITERATIONS_PER_THREAD, thread_data[i].success_count);
    }
}

void test_concurrent_config_init(void) {
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].iterations = ITERATIONS_PER_THREAD;
        thread_data[i].success_count = 0;
        thread_data[i].last_error = NOSTR_OK;
        
        int result = pthread_create(&threads[i], NULL, test_config_thread, &thread_data[i]);
        TEST_ASSERT_EQUAL(0, result);
    }
    
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        TEST_ASSERT_EQUAL(NOSTR_OK, thread_data[i].last_error);
        TEST_ASSERT_EQUAL(ITERATIONS_PER_THREAD, thread_data[i].success_count);
    }
}

void test_concurrent_key_generation(void) {
    nostr_init();
    
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].iterations = ITERATIONS_PER_THREAD;
        thread_data[i].success_count = 0;
        thread_data[i].last_error = NOSTR_OK;
        
        int result = pthread_create(&threads[i], NULL, test_key_generation_thread, &thread_data[i]);
        TEST_ASSERT_EQUAL(0, result);
    }
    
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        TEST_ASSERT_EQUAL(NOSTR_OK, thread_data[i].last_error);
        TEST_ASSERT_EQUAL(ITERATIONS_PER_THREAD, thread_data[i].success_count);
    }
}

static int callback_count = 0;
static pthread_mutex_t callback_lock = PTHREAD_MUTEX_INITIALIZER;

static void test_callback(const nostr_config* old_config, const nostr_config* new_config, void* user_data) {
    pthread_mutex_lock(&callback_lock);
    callback_count++;
    pthread_mutex_unlock(&callback_lock);
    usleep(100);
}

static void* config_update_thread(void* arg) {
    int thread_id = (int)(uintptr_t)arg;
    nostr_config config;
    nostr_config_get_defaults(&config);
    config.max_sessions = 100 + thread_id;
    nostr_config_update(&config);
    return NULL;
}

void test_config_callback_thread_safety(void) {
    callback_count = 0;
    
    nostr_init();
    nostr_config_set_callback(test_callback, NULL);
    
    const int num_updates = 50;
    pthread_t threads[num_updates];
    
    for (int i = 0; i < num_updates; i++) {
        int result = pthread_create(&threads[i], NULL, config_update_thread, (void*)(uintptr_t)i);
        TEST_ASSERT_EQUAL(0, result);
    }
    
    for (int i = 0; i < num_updates; i++) {
        pthread_join(threads[i], NULL);
    }
    
    TEST_ASSERT_EQUAL(num_updates, callback_count);
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_concurrent_initialization);
    RUN_TEST(test_concurrent_config_init);
    RUN_TEST(test_concurrent_key_generation);
    RUN_TEST(test_config_callback_thread_safety);
    
    return UNITY_END();
}