#include "nostr.h"
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#include <string.h>
#elif defined(__linux__) || defined(__GLIBC__)
#define _GNU_SOURCE
#include <string.h>
#endif

int nostr_constant_time_memcmp(const void* a, const void* b, size_t n) {
    const unsigned char* pa = (const unsigned char*)a;
    const unsigned char* pb = (const unsigned char*)b;
    unsigned char diff = 0;
    
    for (size_t i = 0; i < n; i++) {
        diff |= pa[i] ^ pb[i];
    }
    
    return diff;
}

void secure_wipe(void* ptr, size_t len)
{
    if (!ptr || len == 0) {
        return;
    }

#ifdef _WIN32
    SecureZeroMemory(ptr, len);
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
    explicit_bzero(ptr, len);
#elif defined(__linux__) && defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
    explicit_bzero(ptr, len);
#else
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
    __asm__ __volatile__("" ::: "memory");
#endif
}