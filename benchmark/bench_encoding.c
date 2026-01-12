#include "benchmark.h"
#include "nostr_features.h"
#include <string.h>

static void bench_privkey_to_hex_func(void* data) {
    const nostr_privkey* privkey = (const nostr_privkey*)data;
    char hex[65];
    nostr_privkey_to_hex(privkey, hex, sizeof(hex));
}

static void bench_privkey_from_hex_func(void* data) {
    const char* hex = (const char*)data;
    nostr_privkey privkey;
    nostr_privkey_from_hex(hex, &privkey);
}

static void bench_privkey_to_bech32_func(void* data) {
    const nostr_privkey* privkey = (const nostr_privkey*)data;
    char bech32[100];
    nostr_privkey_to_bech32(privkey, bech32, sizeof(bech32));
}

static void bench_privkey_from_bech32_func(void* data) {
    const char* bech32 = (const char*)data;
    nostr_privkey privkey;
    nostr_privkey_from_bech32(bech32, &privkey);
}

static void bench_event_id_to_bech32_func(void* data) {
    const uint8_t* id = (const uint8_t*)data;
    char bech32[100];
    nostr_event_id_to_bech32(id, bech32, sizeof(bech32));
}

static void bench_event_id_from_bech32_func(void* data) {
    const char* bech32 = (const char*)data;
    uint8_t id[32];
    nostr_event_id_from_bech32(bech32, id);
}

#ifdef NOSTR_FEATURE_HD_KEYS
static void bench_hd_key_operations_func(void* data) {
    (void)data;
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = i;

    nostr_hd_key master;
    if (nostr_hd_key_from_seed(seed, sizeof(seed), &master) == NOSTR_OK) {
        nostr_hd_key derived;
        nostr_hd_key_derive_path(&master, NOSTR_HD_PATH_STANDARD, &derived);
    }
}
#endif

void bench_encoding_operations(void) {
    benchmark_result result;
    
    nostr_keypair keypair;
    nostr_keypair_generate(&keypair);
    
    benchmark_run("Private Key To Hex", bench_privkey_to_hex_func, &keypair.privkey, 10000, &result);
    print_benchmark_result("nostr_privkey_to_hex", &result);
    
    const char* test_privkey_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    benchmark_run("Private Key From Hex", bench_privkey_from_hex_func, (void*)test_privkey_hex, 10000, &result);
    print_benchmark_result("nostr_privkey_from_hex", &result);
    
    benchmark_run("Private Key To Bech32", bench_privkey_to_bech32_func, &keypair.privkey, 10000, &result);
    print_benchmark_result("nostr_privkey_to_bech32", &result);
    
    const char* test_privkey_bech32 = "nsec180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsrxj6w5";
    benchmark_run("Private Key From Bech32", bench_privkey_from_bech32_func, (void*)test_privkey_bech32, 10000, &result);
    print_benchmark_result("nostr_privkey_from_bech32", &result);
    
    uint8_t test_event_id[32];
    for (int i = 0; i < 32; i++) test_event_id[i] = i;
    
    benchmark_run("Event ID To Bech32", bench_event_id_to_bech32_func, test_event_id, 10000, &result);
    print_benchmark_result("nostr_event_id_to_bech32", &result);
    
    const char* test_event_bech32 = "note1qqqsyrhqy2gt4qk6ze6fd4hjqq5cv6p7nm9wf4kt08g0sdqx94eqs6jjqaf";
    benchmark_run("Event ID From Bech32", bench_event_id_from_bech32_func, (void*)test_event_bech32, 10000, &result);
    print_benchmark_result("nostr_event_id_from_bech32", &result);
    
#ifdef NOSTR_FEATURE_HD_KEYS
    benchmark_run("HD Key Derivation", bench_hd_key_operations_func, NULL, 1000, &result);
    print_benchmark_result("HD Key Derivation Path", &result);
#endif

    nostr_keypair_destroy(&keypair);
}