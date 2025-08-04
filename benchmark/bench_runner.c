#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "benchmark.h"

int main(int argc, char* argv[]) {
    printf("libnostr-c Performance Benchmark Suite\n");
    printf("=====================================\n\n");
    
    if (nostr_init() != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c\n");
        return 1;
    }
    
    const char* filter = NULL;
    if (argc > 1) {
        filter = argv[1];
        printf("Running benchmarks matching: %s\n\n", filter);
    }
    
    if (!filter || strstr("key", filter)) {
        printf("Key Operations Benchmarks:\n");
        printf("--------------------------\n");
        bench_key_operations();
        printf("\n");
    }
    
    if (!filter || strstr("crypto", filter)) {
        printf("Cryptographic Operations Benchmarks:\n");
        printf("------------------------------------\n");
        bench_crypto_operations();
        printf("\n");
    }
    
    if (!filter || strstr("event", filter)) {
        printf("Event Operations Benchmarks:\n");
        printf("-----------------------------\n");
        bench_event_operations();
        printf("\n");
    }
    
    if (!filter || strstr("encoding", filter)) {
        printf("Encoding Operations Benchmarks:\n");
        printf("-------------------------------\n");
        bench_encoding_operations();
        printf("\n");
    }
    
    if (!filter || strstr("memory", filter)) {
        printf("Memory Operations Benchmarks:\n");
        printf("-----------------------------\n");
        bench_memory_operations();
        printf("\n");
    }
    
    nostr_cleanup();
    return 0;
}