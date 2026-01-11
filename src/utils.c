#if defined(__linux__) || defined(__GLIBC__)
#define _GNU_SOURCE
#endif

#include "nostr.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
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

static int hex_char_to_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int nostr_hex_decode(const char* hex, uint8_t* out, size_t out_len) {
    if (!hex || !out) return -1;
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > out_len) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hex_char_to_nibble(hex[2 * i]);
        int lo = hex_char_to_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(hex_len / 2);
}

void nostr_hex_encode(const uint8_t* bytes, size_t len, char* out) {
    if (!bytes || !out) return;
    for (size_t i = 0; i < len; i++) {
        sprintf(out + 2 * i, "%02x", bytes[i]);
    }
    out[len * 2] = '\0';
}