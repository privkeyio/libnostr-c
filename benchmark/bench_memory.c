#include "benchmark.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t size;
    int count;
} memory_test_data;

static void bench_event_with_many_tags_func(void* data) {
    const memory_test_data* mtd = (const memory_test_data*)data;
    nostr_event* event;
    
    if (nostr_event_create(&event) == NOSTR_OK) {
        event->kind = 1;
        event->created_at = time(NULL);
        
        for (int i = 0; i < mtd->count; i++) {
            const char* tag_values[] = {"p", "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"};
            nostr_event_add_tag(event, tag_values, 2);
        }
        
        nostr_event_destroy(event);
    }
}

static void bench_large_content_func(void* data) {
    const memory_test_data* mtd = (const memory_test_data*)data;
    nostr_event* event;
    
    if (nostr_event_create(&event) == NOSTR_OK) {
        char* large_content = malloc(mtd->size + 1);
        if (large_content) {
            memset(large_content, 'A', mtd->size);
            large_content[mtd->size] = '\0';
            
            nostr_event_set_content(event, large_content);
            nostr_event_compute_id(event);
            
            free(large_content);
        }
        
        nostr_event_destroy(event);
    }
}

static void bench_secure_wipe_func(void* data) {
    const memory_test_data* mtd = (const memory_test_data*)data;
    void* buffer = malloc(mtd->size);
    if (buffer) {
        memset(buffer, 0xAA, mtd->size);
        secure_wipe(buffer, mtd->size);
        free(buffer);
    }
}

static void bench_keypair_lifecycle_func(void* data) {
    const memory_test_data* mtd = (const memory_test_data*)data;
    
    for (int i = 0; i < mtd->count; i++) {
        nostr_keypair keypair;
        nostr_keypair_generate(&keypair);
        
        char hex[65];
        nostr_keypair_export_private_hex(&keypair, hex, sizeof(hex));
        
        nostr_keypair_destroy(&keypair);
    }
}

void bench_memory_operations(void) {
    benchmark_result result;
    
    memory_test_data tag_test = { .count = 10 };
    benchmark_run("Event with 10 Tags", bench_event_with_many_tags_func, &tag_test, 1000, &result);
    print_benchmark_result("Event with 10 tags", &result);
    
    tag_test.count = 100;
    benchmark_run("Event with 100 Tags", bench_event_with_many_tags_func, &tag_test, 100, &result);
    print_benchmark_result("Event with 100 tags", &result);
    
    memory_test_data content_test;
    
    content_test.size = 1024;
    benchmark_run("Event with 1KB Content", bench_large_content_func, &content_test, 1000, &result);
    print_benchmark_result("Event 1KB content", &result);
    
    content_test.size = 10240;
    benchmark_run("Event with 10KB Content", bench_large_content_func, &content_test, 100, &result);
    print_benchmark_result("Event 10KB content", &result);
    
    content_test.size = 102400;
    benchmark_run("Event with 100KB Content", bench_large_content_func, &content_test, 10, &result);
    print_benchmark_result("Event 100KB content", &result);
    
    memory_test_data wipe_test;
    
    wipe_test.size = 32;
    benchmark_run("Secure Wipe 32 bytes", bench_secure_wipe_func, &wipe_test, 100000, &result);
    print_benchmark_result("secure_wipe (32 bytes)", &result);
    print_throughput("secure_wipe (32 bytes)", &result, 32);
    
    wipe_test.size = 1024;
    benchmark_run("Secure Wipe 1KB", bench_secure_wipe_func, &wipe_test, 10000, &result);
    print_benchmark_result("secure_wipe (1KB)", &result);
    print_throughput("secure_wipe (1KB)", &result, 1024);
    
    wipe_test.size = 4096;
    benchmark_run("Secure Wipe 4KB", bench_secure_wipe_func, &wipe_test, 10000, &result);
    print_benchmark_result("secure_wipe (4KB)", &result);
    print_throughput("secure_wipe (4KB)", &result, 4096);
    
    memory_test_data lifecycle_test = { .count = 10 };
    benchmark_run("Keypair Lifecycle (10x)", bench_keypair_lifecycle_func, &lifecycle_test, 1000, &result);
    print_benchmark_result("Keypair batch lifecycle", &result);
}