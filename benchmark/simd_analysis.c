#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include "benchmark.h"

#ifdef __SSE2__
#define HAVE_SSE2 1
#endif

#ifdef __AVX2__
#define HAVE_AVX2 1
#endif

static int scalar_memcmp(const void* a, const void* b, size_t n) {
    const unsigned char* pa = (const unsigned char*)a;
    const unsigned char* pb = (const unsigned char*)b;
    
    for (size_t i = 0; i < n; i++) {
        if (pa[i] != pb[i]) {
            return pa[i] - pb[i];
        }
    }
    return 0;
}

#ifdef HAVE_SSE2
static int sse2_memcmp(const void* a, const void* b, size_t n) {
    const unsigned char* pa = (const unsigned char*)a;
    const unsigned char* pb = (const unsigned char*)b;
    size_t chunks = n / 16;
    
    for (size_t i = 0; i < chunks; i++) {
        __m128i va = _mm_loadu_si128((const __m128i*)(pa + i * 16));
        __m128i vb = _mm_loadu_si128((const __m128i*)(pb + i * 16));
        __m128i cmp = _mm_cmpeq_epi8(va, vb);
        
        if (_mm_movemask_epi8(cmp) != 0xFFFF) {
            return scalar_memcmp(pa + i * 16, pb + i * 16, 16);
        }
    }
    
    size_t remaining = n % 16;
    if (remaining > 0) {
        return scalar_memcmp(pa + chunks * 16, pb + chunks * 16, remaining);
    }
    
    return 0;
}
#endif

#ifdef HAVE_AVX2
static int avx2_memcmp(const void* a, const void* b, size_t n) {
    const unsigned char* pa = (const unsigned char*)a;
    const unsigned char* pb = (const unsigned char*)b;
    size_t chunks = n / 32;
    
    for (size_t i = 0; i < chunks; i++) {
        __m256i va = _mm256_loadu_si256((const __m256i*)(pa + i * 32));
        __m256i vb = _mm256_loadu_si256((const __m256i*)(pb + i * 32));
        __m256i cmp = _mm256_cmpeq_epi8(va, vb);
        
        if (_mm256_movemask_epi8(cmp) != 0xFFFFFFFF) {
            return scalar_memcmp(pa + i * 32, pb + i * 32, 32);
        }
    }
    
    size_t remaining = n % 32;
    if (remaining > 0) {
        return scalar_memcmp(pa + chunks * 32, pb + chunks * 32, remaining);
    }
    
    return 0;
}
#endif

static void scalar_memset_func(void* data) {
    uint8_t* buffer = (uint8_t*)data;
    memset(buffer, 0, 1024);
}

#ifdef HAVE_SSE2
static void sse2_memset_func(void* data) {
    uint8_t* buffer = (uint8_t*)data;
    __m128i zero = _mm_setzero_si128();
    
    for (size_t i = 0; i < 1024; i += 16) {
        _mm_storeu_si128((__m128i*)(buffer + i), zero);
    }
}
#endif

#ifdef HAVE_AVX2
static void avx2_memset_func(void* data) {
    uint8_t* buffer = (uint8_t*)data;
    __m256i zero = _mm256_setzero_si256();
    
    for (size_t i = 0; i < 1024; i += 32) {
        _mm256_storeu_si256((__m256i*)(buffer + i), zero);
    }
}
#endif

static void bench_memcmp_variants(void) {
    printf("Memory Comparison SIMD Analysis:\n");
    printf("--------------------------------\n");
    
    const size_t sizes[] = {32, 64, 128, 256, 512, 1024};
    const int num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    
    for (int i = 0; i < num_sizes; i++) {
        size_t size = sizes[i];
        uint8_t* buffer1 = malloc(size);
        uint8_t* buffer2 = malloc(size);
        
        for (size_t j = 0; j < size; j++) {
            buffer1[j] = j & 0xFF;
            buffer2[j] = j & 0xFF;
        }
        
        buffer2[size - 1] = 0xFF;
        
        benchmark_timer timer;
        uint64_t iterations = 100000;
        
        benchmark_start(&timer, "scalar");
        for (uint64_t j = 0; j < iterations; j++) {
            scalar_memcmp(buffer1, buffer2, size);
        }
        benchmark_end(&timer);
        uint64_t scalar_time = benchmark_elapsed_ns(&timer);
        
        printf("%4zu bytes - Scalar: %8.2f ns/op", size, (double)scalar_time / iterations);
        
#ifdef HAVE_SSE2
        benchmark_start(&timer, "sse2");
        for (uint64_t j = 0; j < iterations; j++) {
            sse2_memcmp(buffer1, buffer2, size);
        }
        benchmark_end(&timer);
        uint64_t sse2_time = benchmark_elapsed_ns(&timer);
        
        printf(", SSE2: %8.2f ns/op (%.1fx)", 
               (double)sse2_time / iterations,
               (double)scalar_time / sse2_time);
#endif

#ifdef HAVE_AVX2
        benchmark_start(&timer, "avx2");
        for (uint64_t j = 0; j < iterations; j++) {
            avx2_memcmp(buffer1, buffer2, size);
        }
        benchmark_end(&timer);
        uint64_t avx2_time = benchmark_elapsed_ns(&timer);
        
        printf(", AVX2: %8.2f ns/op (%.1fx)", 
               (double)avx2_time / iterations,
               (double)scalar_time / avx2_time);
#endif
        
        printf("\n");
        
        free(buffer1);
        free(buffer2);
    }
    
    printf("\n");
}

static void bench_memset_variants(void) {
    printf("Memory Set SIMD Analysis:\n");
    printf("-------------------------\n");
    
    uint8_t* buffer = malloc(1024);
    benchmark_result result;
    
    benchmark_run("Scalar memset", scalar_memset_func, buffer, 100000, &result);
    print_benchmark_result("Scalar memset (1KB)", &result);
    print_throughput("Scalar memset (1KB)", &result, 1024);
    
#ifdef HAVE_SSE2
    benchmark_run("SSE2 memset", sse2_memset_func, buffer, 100000, &result);
    print_benchmark_result("SSE2 memset (1KB)", &result);
    print_throughput("SSE2 memset (1KB)", &result, 1024);
#endif

#ifdef HAVE_AVX2
    benchmark_run("AVX2 memset", avx2_memset_func, buffer, 100000, &result);
    print_benchmark_result("AVX2 memset (1KB)", &result);
    print_throughput("AVX2 memset (1KB)", &result, 1024);
#endif
    
    free(buffer);
    printf("\n");
}

int main(int argc, char* argv[]) {
    printf("libnostr-c SIMD Optimization Analysis\n");
    printf("=====================================\n\n");
    
    printf("CPU SIMD Support:\n");
#ifdef HAVE_SSE2
    printf("  SSE2: Available\n");
#else
    printf("  SSE2: Not available\n");
#endif

#ifdef HAVE_AVX2
    printf("  AVX2: Available\n");
#else
    printf("  AVX2: Not available\n");
#endif
    printf("\n");
    
    if (nostr_init() != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c\n");
        return 1;
    }
    
    bench_memcmp_variants();
    bench_memset_variants();
    
    printf("SIMD Optimization Recommendations:\n");
    printf("----------------------------------\n");
    printf("1. For memory comparison operations (like constant-time memcmp):\n");
#ifdef HAVE_AVX2
    printf("   - AVX2 available: Consider vectorized implementation for large buffers\n");
#elif defined(HAVE_SSE2)
    printf("   - SSE2 available: Consider vectorized implementation for buffers >= 64 bytes\n");
#else
    printf("   - No SIMD available: Stick with scalar implementation\n");
#endif
    
    printf("2. For memory clearing (secure_wipe):\n");
#ifdef HAVE_AVX2
    printf("   - AVX2 available: Significant speedup possible for large key/buffer clearing\n");
#elif defined(HAVE_SSE2)
    printf("   - SSE2 available: Moderate speedup for buffer clearing operations\n");
#else
    printf("   - No SIMD available: Focus on compiler barriers and volatility\n");
#endif
    
    printf("3. Hash operations could benefit from SHA-NI if available\n");
    printf("4. Large JSON parsing/generation could use SIMD string operations\n");
    
    nostr_cleanup();
    return 0;
}