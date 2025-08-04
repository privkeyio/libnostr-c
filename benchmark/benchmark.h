#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include "nostr.h"

#ifdef __MACH__
#include <mach/mach_time.h>
#endif

typedef struct {
    uint64_t start_ns;
    uint64_t end_ns;
    const char* name;
} benchmark_timer;

typedef struct {
    double min_ns;
    double max_ns;
    double avg_ns;
    uint64_t iterations;
} benchmark_result;

static inline uint64_t get_nanoseconds(void) {
#ifdef __MACH__
    static mach_timebase_info_data_t timebase = {0, 0};
    if (timebase.denom == 0) {
        mach_timebase_info(&timebase);
    }
    return mach_absolute_time() * timebase.numer / timebase.denom;
#elif defined(_WIN32)
    LARGE_INTEGER frequency, counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (counter.QuadPart * 1000000000ULL) / frequency.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

static inline void benchmark_start(benchmark_timer* timer, const char* name) {
    timer->name = name;
    timer->start_ns = get_nanoseconds();
}

static inline void benchmark_end(benchmark_timer* timer) {
    timer->end_ns = get_nanoseconds();
}

static inline uint64_t benchmark_elapsed_ns(const benchmark_timer* timer) {
    return timer->end_ns - timer->start_ns;
}

static inline void benchmark_run(const char* name, void (*func)(void*), void* data, 
                                 uint64_t iterations, benchmark_result* result) {
    benchmark_timer timer;
    uint64_t total_ns = 0;
    uint64_t min_ns = UINT64_MAX;
    uint64_t max_ns = 0;
    
    for (uint64_t i = 0; i < iterations; i++) {
        benchmark_start(&timer, name);
        func(data);
        benchmark_end(&timer);
        
        uint64_t elapsed = benchmark_elapsed_ns(&timer);
        total_ns += elapsed;
        if (elapsed < min_ns) min_ns = elapsed;
        if (elapsed > max_ns) max_ns = elapsed;
    }
    
    result->min_ns = (double)min_ns;
    result->max_ns = (double)max_ns;
    result->avg_ns = (double)total_ns / iterations;
    result->iterations = iterations;
}

static inline void print_benchmark_result(const char* name, const benchmark_result* result) {
    printf("%-40s: %8.2f ns/op (min: %8.2f, max: %8.2f) [%lu ops]\n",
           name, result->avg_ns, result->min_ns, result->max_ns, result->iterations);
}

static inline void print_throughput(const char* name, const benchmark_result* result, 
                                   uint64_t bytes_per_op) {
    double ops_per_sec = 1e9 / result->avg_ns;
    double mb_per_sec = (ops_per_sec * bytes_per_op) / (1024 * 1024);
    printf("%-40s: %8.2f MB/s (%8.0f ops/sec)\n", name, mb_per_sec, ops_per_sec);
}

void bench_key_operations(void);
void bench_crypto_operations(void);
void bench_event_operations(void);
void bench_encoding_operations(void);
void bench_memory_operations(void);

#endif