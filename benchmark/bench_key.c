#include "benchmark.h"

static void bench_key_generate_func(void* data) {
    (void)data;
    nostr_privkey privkey;
    nostr_key pubkey;
    nostr_key_generate(&privkey, &pubkey);
}

static void bench_keypair_generate_func(void* data) {
    (void)data;
    nostr_keypair keypair;
    nostr_keypair_generate(&keypair);
    nostr_keypair_destroy(&keypair);
}

static void bench_key_from_hex_func(void* data) {
    const char* hex = (const char*)data;
    nostr_key key;
    nostr_key_from_hex(hex, &key);
}

static void bench_key_to_hex_func(void* data) {
    const nostr_key* key = (const nostr_key*)data;
    char hex[65];
    nostr_key_to_hex(key, hex, sizeof(hex));
}

static void bench_key_to_bech32_func(void* data) {
    const nostr_key* key = (const nostr_key*)data;
    char bech32[100];
    nostr_key_to_bech32(key, "npub", bech32, sizeof(bech32));
}

static void bench_key_from_bech32_func(void* data) {
    const char* bech32 = (const char*)data;
    nostr_key key;
    nostr_key_from_bech32(bech32, &key);
}

static void bench_ecdh_func(void* data) {
    const nostr_keypair* keypair = (const nostr_keypair*)data;
    uint8_t shared_secret[32];
    nostr_key_ecdh(&keypair->privkey, &keypair->pubkey, shared_secret);
}

void bench_key_operations(void) {
    benchmark_result result;
    
    benchmark_run("Key Generation", bench_key_generate_func, NULL, 1000, &result);
    print_benchmark_result("nostr_key_generate", &result);
    
    benchmark_run("Keypair Generation", bench_keypair_generate_func, NULL, 1000, &result);
    print_benchmark_result("nostr_keypair_generate", &result);
    
    const char* test_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    benchmark_run("Key From Hex", bench_key_from_hex_func, (void*)test_hex, 10000, &result);
    print_benchmark_result("nostr_key_from_hex", &result);
    
    nostr_key test_key;
    nostr_key_from_hex(test_hex, &test_key);
    
    benchmark_run("Key To Hex", bench_key_to_hex_func, &test_key, 10000, &result);
    print_benchmark_result("nostr_key_to_hex", &result);
    
    benchmark_run("Key To Bech32", bench_key_to_bech32_func, &test_key, 10000, &result);
    print_benchmark_result("nostr_key_to_bech32", &result);
    
    const char* test_bech32 = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    benchmark_run("Key From Bech32", bench_key_from_bech32_func, (void*)test_bech32, 10000, &result);
    print_benchmark_result("nostr_key_from_bech32", &result);
    
    nostr_keypair test_keypair;
    nostr_keypair_generate(&test_keypair);
    
    benchmark_run("ECDH Operation", bench_ecdh_func, &test_keypair, 1000, &result);
    print_benchmark_result("nostr_key_ecdh", &result);
    
    nostr_keypair_destroy(&test_keypair);
}