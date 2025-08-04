#include "benchmark.h"
#include "nostr_features.h"
#include <string.h>
#include <stdlib.h>

// Macros for disabled features - redirect to stubs
#ifndef NOSTR_FEATURE_NIP44
#define nostr_nip44_encrypt stub_nip44_encrypt
#define nostr_nip44_decrypt stub_nip44_decrypt
static inline nostr_error_t stub_nip44_encrypt(const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey, const char* plaintext, size_t plaintext_len, char** ciphertext) {
    *ciphertext = strdup("disabled");
    return NOSTR_ERR_NOT_SUPPORTED;
}
static inline nostr_error_t stub_nip44_decrypt(const nostr_privkey* recipient_privkey, const nostr_key* sender_pubkey, const char* ciphertext, char** plaintext, size_t* plaintext_len) {
    *plaintext = strdup("disabled");
    *plaintext_len = 8;
    return NOSTR_ERR_NOT_SUPPORTED;
}
#endif

#ifndef NOSTR_FEATURE_NIP04
#define nostr_nip04_encrypt stub_nip04_encrypt
#define nostr_nip04_decrypt stub_nip04_decrypt
static inline nostr_error_t stub_nip04_encrypt(const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey, const char* plaintext, char** ciphertext) {
    *ciphertext = strdup("disabled");
    return NOSTR_ERR_NOT_SUPPORTED;
}
static inline nostr_error_t stub_nip04_decrypt(const nostr_privkey* recipient_privkey, const nostr_key* sender_pubkey, const char* ciphertext, char** plaintext) {
    *plaintext = strdup("disabled");
    return NOSTR_ERR_NOT_SUPPORTED;
}
#endif

typedef struct {
    nostr_privkey sender_privkey;
    nostr_key recipient_pubkey;
    const char* plaintext;
    size_t plaintext_len;
} encrypt_data;

typedef struct {
    nostr_privkey recipient_privkey;
    nostr_key sender_pubkey;
    char* ciphertext;
} decrypt_data;

static void bench_nip44_encrypt_func(void* data) {
    encrypt_data* ed = (encrypt_data*)data;
    char* ciphertext;
    nostr_nip44_encrypt(&ed->sender_privkey, &ed->recipient_pubkey, 
                        ed->plaintext, ed->plaintext_len, &ciphertext);
    if (ciphertext) free(ciphertext);
}

static void bench_nip44_decrypt_func(void* data) {
    decrypt_data* dd = (decrypt_data*)data;
    char* plaintext;
    size_t plaintext_len;
    nostr_nip44_decrypt(&dd->recipient_privkey, &dd->sender_pubkey,
                        dd->ciphertext, &plaintext, &plaintext_len);
    if (plaintext) free(plaintext);
}

static void bench_nip04_encrypt_func(void* data) {
    encrypt_data* ed = (encrypt_data*)data;
    char* ciphertext;
    nostr_nip04_encrypt(&ed->sender_privkey, &ed->recipient_pubkey, 
                        ed->plaintext, &ciphertext);
    if (ciphertext) free(ciphertext);
}

static void bench_nip04_decrypt_func(void* data) {
    decrypt_data* dd = (decrypt_data*)data;
    char* plaintext;
    nostr_nip04_decrypt(&dd->recipient_privkey, &dd->sender_pubkey,
                        dd->ciphertext, &plaintext);
    if (plaintext) free(plaintext);
}

static void bench_constant_time_memcmp_func(void* data) {
    const uint8_t* test_data = (const uint8_t*)data;
    nostr_constant_time_memcmp(test_data, test_data + 32, 32);
}

void bench_crypto_operations(void) {
    benchmark_result result;
    
    nostr_keypair sender, recipient;
    nostr_keypair_generate(&sender);
    nostr_keypair_generate(&recipient);
    
    const char* test_messages[] = {
        "Hello, world!",
        "This is a longer test message that might show different performance characteristics for encryption and decryption operations.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
    };
    
    for (int i = 0; i < 3; i++) {
        const char* msg = test_messages[i];
        size_t msg_len = strlen(msg);
        
        encrypt_data ed = {
            .sender_privkey = sender.privkey,
            .recipient_pubkey = recipient.pubkey,
            .plaintext = msg,
            .plaintext_len = msg_len
        };
        
        char benchmark_name[100];
        snprintf(benchmark_name, sizeof(benchmark_name), "NIP-44 Encrypt (%zu bytes)", msg_len);
        benchmark_run(benchmark_name, bench_nip44_encrypt_func, &ed, 1000, &result);
        print_benchmark_result(benchmark_name, &result);
        print_throughput(benchmark_name, &result, msg_len);
        
        char* ciphertext;
        if (nostr_nip44_encrypt(&ed.sender_privkey, &ed.recipient_pubkey, 
                               ed.plaintext, ed.plaintext_len, &ciphertext) == NOSTR_OK) {
            decrypt_data dd = {
                .recipient_privkey = recipient.privkey,
                .sender_pubkey = sender.pubkey,
                .ciphertext = ciphertext
            };
            
            snprintf(benchmark_name, sizeof(benchmark_name), "NIP-44 Decrypt (%zu bytes)", msg_len);
            benchmark_run(benchmark_name, bench_nip44_decrypt_func, &dd, 1000, &result);
            print_benchmark_result(benchmark_name, &result);
            print_throughput(benchmark_name, &result, msg_len);
            
            free(ciphertext);
        }
        
        snprintf(benchmark_name, sizeof(benchmark_name), "NIP-04 Encrypt (%zu bytes)", msg_len);
        benchmark_run(benchmark_name, bench_nip04_encrypt_func, &ed, 1000, &result);
        print_benchmark_result(benchmark_name, &result);
        print_throughput(benchmark_name, &result, msg_len);
        
        char* nip04_ciphertext;
        if (nostr_nip04_encrypt(&ed.sender_privkey, &ed.recipient_pubkey, 
                               ed.plaintext, &nip04_ciphertext) == NOSTR_OK) {
            decrypt_data dd = {
                .recipient_privkey = recipient.privkey,
                .sender_pubkey = sender.pubkey,
                .ciphertext = nip04_ciphertext
            };
            
            snprintf(benchmark_name, sizeof(benchmark_name), "NIP-04 Decrypt (%zu bytes)", msg_len);
            benchmark_run(benchmark_name, bench_nip04_decrypt_func, &dd, 1000, &result);
            print_benchmark_result(benchmark_name, &result);
            print_throughput(benchmark_name, &result, msg_len);
            
            free(nip04_ciphertext);
        }
    }
    
    uint8_t test_data[64];
    for (int i = 0; i < 64; i++) test_data[i] = i;
    
    benchmark_run("Constant Time Memcmp (32 bytes)", bench_constant_time_memcmp_func, test_data, 100000, &result);
    print_benchmark_result("nostr_constant_time_memcmp", &result);
    
    nostr_keypair_destroy(&sender);
    nostr_keypair_destroy(&recipient);
}