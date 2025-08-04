#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include "benchmark.h"
#include "nostr_features.h"

// Stub functions for disabled features
#ifndef NOSTR_FEATURE_NIP44
static inline nostr_error_t nostr_nip44_encrypt(const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey, const char* plaintext, size_t plaintext_len, char** ciphertext) {
    *ciphertext = strdup("disabled");
    return NOSTR_ERR_NOT_SUPPORTED;
}
#endif

#ifndef NOSTR_FEATURE_NIP04
static inline nostr_error_t nostr_nip04_encrypt(const nostr_privkey* sender_privkey, const nostr_key* recipient_pubkey, const char* plaintext, char** ciphertext) {
    *ciphertext = strdup("disabled");
    return NOSTR_ERR_NOT_SUPPORTED;
}
#endif

typedef struct {
    size_t peak_rss;
    size_t current_rss;
    size_t allocations;
    size_t deallocations;
} memory_stats;

static size_t get_peak_rss(void) {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss * 1024;
}

static size_t get_current_rss(void) {
    FILE* file = fopen("/proc/self/status", "r");
    if (!file) return 0;
    
    char line[128];
    size_t rss = 0;
    
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "VmRSS: %zu kB", &rss) == 1) {
            rss *= 1024;
            break;
        }
    }
    
    fclose(file);
    return rss;
}

static void analyze_event_memory_patterns(void) {
    printf("Event Memory Pattern Analysis:\n");
    printf("------------------------------\n");
    
    size_t baseline_rss = get_current_rss();
    
    const int event_counts[] = {1, 10, 100, 1000, 10000};
    const int num_tests = sizeof(event_counts) / sizeof(event_counts[0]);
    
    for (int i = 0; i < num_tests; i++) {
        int count = event_counts[i];
        nostr_event** events = malloc(count * sizeof(nostr_event*));
        
        size_t before_rss = get_current_rss();
        
        for (int j = 0; j < count; j++) {
            nostr_event_create(&events[j]);
            events[j]->kind = 1;
            events[j]->created_at = time(NULL);
            nostr_event_set_content(events[j], "Test event content for memory analysis");
            
            const char* tag_values[] = {"p", "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"};
            nostr_event_add_tag(events[j], tag_values, 2);
        }
        
        size_t after_create_rss = get_current_rss();
        
        for (int j = 0; j < count; j++) {
            nostr_event_destroy(events[j]);
        }
        
        size_t after_destroy_rss = get_current_rss();
        
        free(events);
        
        printf("%5d events: Create +%zu KB, Destroy -%zu KB, Per-event: %.1f bytes\n",
               count,
               (after_create_rss - before_rss) / 1024,
               (after_create_rss - after_destroy_rss) / 1024,
               (double)(after_create_rss - before_rss) / count);
    }
    
    printf("\n");
}

static void analyze_tag_arena_efficiency(void) {
    printf("Tag Arena Memory Efficiency Analysis:\n");
    printf("------------------------------------\n");
    
    const int tag_counts[] = {1, 10, 50, 100, 500};
    const int num_tests = sizeof(tag_counts) / sizeof(tag_counts[0]);
    
    for (int i = 0; i < num_tests; i++) {
        int tag_count = tag_counts[i];
        
        size_t before_rss = get_current_rss();
        
        nostr_event* event;
        nostr_event_create(&event);
        
        for (int j = 0; j < tag_count; j++) {
            char tag_value[65];
            snprintf(tag_value, sizeof(tag_value), "tag_%d_%032d", j, j);
            const char* tag_values[] = {"test", tag_value};
            nostr_event_add_tag(event, tag_values, 2);
        }
        
        size_t after_rss = get_current_rss();
        
        printf("%3d tags: %zu bytes total, %.1f bytes per tag\n",
               tag_count,
               after_rss - before_rss,
               (double)(after_rss - before_rss) / tag_count);
        
        nostr_event_destroy(event);
    }
    
    printf("\n");
}

static void analyze_crypto_memory_usage(void) {
    printf("Cryptographic Operations Memory Usage:\n");
    printf("-------------------------------------\n");
    
    nostr_keypair sender, recipient;
    nostr_keypair_generate(&sender);
    nostr_keypair_generate(&recipient);
    
    const char* test_messages[] = {
        "Short message",
        "Medium length message that tests memory allocation patterns for encryption operations",
        "Very long message that contains a lot of text to analyze how memory allocation scales with message size in both NIP-04 and NIP-44 encryption schemes. This message is intentionally verbose to test larger allocations."
    };
    
    for (int i = 0; i < 3; i++) {
        const char* msg = test_messages[i];
        size_t msg_len = strlen(msg);
        
        printf("Message size: %zu bytes\n", msg_len);
        
        size_t before_nip44 = get_current_rss();
        char* nip44_ciphertext;
        nostr_nip44_encrypt(&sender.privkey, &recipient.pubkey, msg, msg_len, &nip44_ciphertext);
        size_t after_nip44 = get_current_rss();
        
        if (nip44_ciphertext) {
            printf("  NIP-44 encrypt: %zu bytes overhead, ciphertext: %zu bytes\n",
                   after_nip44 - before_nip44, strlen(nip44_ciphertext));
            free(nip44_ciphertext);
        }
        
        size_t before_nip04 = get_current_rss();
        char* nip04_ciphertext;
        nostr_nip04_encrypt(&sender.privkey, &recipient.pubkey, msg, &nip04_ciphertext);
        size_t after_nip04 = get_current_rss();
        
        if (nip04_ciphertext) {
            printf("  NIP-04 encrypt: %zu bytes overhead, ciphertext: %zu bytes\n",
                   after_nip04 - before_nip04, strlen(nip04_ciphertext));
            free(nip04_ciphertext);
        }
        
        printf("\n");
    }
    
    nostr_keypair_destroy(&sender);
    nostr_keypair_destroy(&recipient);
}

int main(int argc, char* argv[]) {
    printf("libnostr-c Memory Analysis Tool\n");
    printf("===============================\n\n");
    
    if (nostr_init() != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c\n");
        return 1;
    }
    
    printf("Peak RSS at start: %zu KB\n", get_peak_rss() / 1024);
    printf("Current RSS at start: %zu KB\n\n", get_current_rss() / 1024);
    
    analyze_event_memory_patterns();
    analyze_tag_arena_efficiency();
    analyze_crypto_memory_usage();
    
    printf("Final Memory Usage:\n");
    printf("Peak RSS: %zu KB\n", get_peak_rss() / 1024);
    printf("Current RSS: %zu KB\n", get_current_rss() / 1024);
    
    nostr_cleanup();
    return 0;
}