#include "benchmark.h"
#include <string.h>
#include <stdlib.h>

typedef struct {
    nostr_event* event;
    nostr_privkey* privkey;
} event_sign_data;

static void bench_event_create_func(void* data) {
    (void)data;
    nostr_event* event;
    nostr_error_t result = nostr_event_create(&event);
    if (result == NOSTR_OK) {
        nostr_event_destroy(event);
    }
}

static void bench_event_set_content_func(void* data) {
    const char* content = (const char*)data;
    nostr_event* event;
    if (nostr_event_create(&event) == NOSTR_OK) {
        nostr_event_set_content(event, content);
        nostr_event_destroy(event);
    }
}

static void bench_event_add_tag_func(void* data) {
    (void)data;
    nostr_event* event;
    if (nostr_event_create(&event) == NOSTR_OK) {
        const char* tag_values[] = {"p", "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"};
        nostr_event_add_tag(event, tag_values, 2);
        nostr_event_destroy(event);
    }
}

static void bench_event_compute_id_func(void* data) {
    nostr_event* event = (nostr_event*)data;
    nostr_event_compute_id(event);
}

static void bench_event_sign_func(void* data) {
    event_sign_data* esd = (event_sign_data*)data;
    nostr_event_sign(esd->event, esd->privkey);
}

static void bench_event_verify_func(void* data) {
    nostr_event* event = (nostr_event*)data;
    nostr_event_verify(event);
}

static void bench_event_to_json_func(void* data) {
    nostr_event* event = (nostr_event*)data;
    char* json;
    if (nostr_event_to_json(event, &json) == NOSTR_OK) {
        free(json);
    }
}

static void bench_event_from_json_func(void* data) {
    const char* json = (const char*)data;
    nostr_event* event;
    if (nostr_event_from_json(json, &event) == NOSTR_OK) {
        nostr_event_destroy(event);
    }
}

void bench_event_operations(void) {
    benchmark_result result;
    
    benchmark_run("Event Creation", bench_event_create_func, NULL, 10000, &result);
    print_benchmark_result("nostr_event_create", &result);
    
    const char* test_contents[] = {
        "Hello, Nostr!",
        "This is a medium-length message that tests event content handling performance characteristics.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
    };
    
    for (int i = 0; i < 3; i++) {
        char benchmark_name[100];
        snprintf(benchmark_name, sizeof(benchmark_name), "Event Set Content (%zu bytes)", strlen(test_contents[i]));
        benchmark_run(benchmark_name, bench_event_set_content_func, (void*)test_contents[i], 10000, &result);
        print_benchmark_result(benchmark_name, &result);
    }
    
    benchmark_run("Event Add Tag", bench_event_add_tag_func, NULL, 10000, &result);
    print_benchmark_result("nostr_event_add_tag", &result);
    
    nostr_event* test_event;
    nostr_keypair keypair;
    nostr_keypair_generate(&keypair);
    
    if (nostr_event_create(&test_event) == NOSTR_OK) {
        test_event->kind = 1;
        test_event->created_at = time(NULL);
        test_event->pubkey = keypair.pubkey;
        nostr_event_set_content(test_event, "Test event for benchmarking");
        
        const char* tag_values[] = {"p", "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"};
        nostr_event_add_tag(test_event, tag_values, 2);
        
        benchmark_run("Event Compute ID", bench_event_compute_id_func, test_event, 10000, &result);
        print_benchmark_result("nostr_event_compute_id", &result);
        
        event_sign_data esd = { .event = test_event, .privkey = &keypair.privkey };
        benchmark_run("Event Sign", bench_event_sign_func, &esd, 1000, &result);
        print_benchmark_result("nostr_event_sign", &result);
        
        nostr_event_sign(test_event, &keypair.privkey);
        
        benchmark_run("Event Verify", bench_event_verify_func, test_event, 1000, &result);
        print_benchmark_result("nostr_event_verify", &result);
        
        benchmark_run("Event To JSON", bench_event_to_json_func, test_event, 10000, &result);
        print_benchmark_result("nostr_event_to_json", &result);
        
        char* json;
        if (nostr_event_to_json(test_event, &json) == NOSTR_OK) {
            benchmark_run("Event From JSON", bench_event_from_json_func, json, 10000, &result);
            print_benchmark_result("nostr_event_from_json", &result);
            free(json);
        }
        
        nostr_event_destroy(test_event);
    }
    
    nostr_keypair_destroy(&keypair);
}