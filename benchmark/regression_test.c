#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "benchmark.h"

#define MAX_BASELINE_TESTS 50
#define REGRESSION_THRESHOLD 1.2

typedef struct {
    char name[128];
    double baseline_ns;
    double current_ns;
    double ratio;
    int regression;
} regression_result;

typedef struct {
    regression_result tests[MAX_BASELINE_TESTS];
    int count;
    int regressions;
    int improvements;
} regression_report;

static void load_baseline(const char* filename, regression_report* report) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("No baseline file found at %s, creating new baseline...\n\n", filename);
        return;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), file) && report->count < MAX_BASELINE_TESTS) {
        char name[128];
        double baseline_ns;
        
        if (sscanf(line, "%127s %lf", name, &baseline_ns) == 2) {
            strcpy(report->tests[report->count].name, name);
            report->tests[report->count].baseline_ns = baseline_ns;
            report->count++;
        }
    }
    
    fclose(file);
    printf("Loaded %d baseline measurements from %s\n\n", report->count, filename);
}

static void save_baseline(const char* filename, const regression_report* report) {
    FILE* file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Failed to save baseline to %s\n", filename);
        return;
    }
    
    for (int i = 0; i < report->count; i++) {
        fprintf(file, "%s %.2f\n", report->tests[i].name, report->tests[i].current_ns);
    }
    
    fclose(file);
    printf("Saved %d baseline measurements to %s\n", report->count, filename);
}

static void add_measurement(regression_report* report, const char* name, double current_ns) {
    int found = -1;
    
    for (int i = 0; i < report->count; i++) {
        if (strcmp(report->tests[i].name, name) == 0) {
            found = i;
            break;
        }
    }
    
    if (found >= 0) {
        report->tests[found].current_ns = current_ns;
        report->tests[found].ratio = current_ns / report->tests[found].baseline_ns;
        report->tests[found].regression = (report->tests[found].ratio > REGRESSION_THRESHOLD);
        
        if (report->tests[found].regression) {
            report->regressions++;
        } else if (report->tests[found].ratio < 0.9) {
            report->improvements++;
        }
    } else {
        if (report->count < MAX_BASELINE_TESTS) {
            strcpy(report->tests[report->count].name, name);
            report->tests[report->count].baseline_ns = 0.0;
            report->tests[report->count].current_ns = current_ns;
            report->tests[report->count].ratio = 0.0;
            report->tests[report->count].regression = 0;
            report->count++;
        }
    }
}

static void key_generate_wrapper(void* data) {
    (void)data;
    nostr_privkey privkey;
    nostr_key pubkey;
    nostr_key_generate(&privkey, &pubkey);
}

static void run_regression_benchmarks(regression_report* report) {
    benchmark_result result;
    
    nostr_privkey privkey;
    nostr_key pubkey;
    nostr_key_generate(&privkey, &pubkey);
    
    benchmark_run("key_generation", key_generate_wrapper, NULL, 1000, &result);
    add_measurement(report, "key_generation", result.avg_ns);
    
    const char* test_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    nostr_key key;
    
    void hex_to_key_wrapper(void* data) {
        nostr_key_from_hex((const char*)data, &key);
    }
    
    benchmark_run("key_from_hex", hex_to_key_wrapper, (void*)test_hex, 10000, &result);
    add_measurement(report, "key_from_hex", result.avg_ns);
    
    void key_to_hex_wrapper(void* data) {
        char hex[65];
        nostr_key_to_hex((const nostr_key*)data, hex, sizeof(hex));
    }
    
    benchmark_run("key_to_hex", key_to_hex_wrapper, &key, 10000, &result);
    add_measurement(report, "key_to_hex", result.avg_ns);
    
    nostr_event* event;
    nostr_event_create(&event);
    event->kind = 1;
    event->created_at = time(NULL);
    event->pubkey = pubkey;
    nostr_event_set_content(event, "Test event content");
    
    void event_compute_id_wrapper(void* data) {
        nostr_event_compute_id((nostr_event*)data);
    }
    
    benchmark_run("event_compute_id", event_compute_id_wrapper, event, 10000, &result);
    add_measurement(report, "event_compute_id", result.avg_ns);
    
    void event_sign_wrapper(void* data) {
        nostr_event_sign((nostr_event*)data, &privkey);
    }
    
    benchmark_run("event_sign", event_sign_wrapper, event, 1000, &result);
    add_measurement(report, "event_sign", result.avg_ns);
    
    nostr_event_sign(event, &privkey);
    
    void event_verify_wrapper(void* data) {
        nostr_event_verify((const nostr_event*)data);
    }
    
    benchmark_run("event_verify", event_verify_wrapper, event, 1000, &result);
    add_measurement(report, "event_verify", result.avg_ns);
    
    nostr_keypair sender, recipient;
    nostr_keypair_generate(&sender);
    nostr_keypair_generate(&recipient);
    
    const char* test_message = "Test message for encryption benchmarks";
    
    typedef struct {
        nostr_privkey* sender_privkey;
        nostr_key* recipient_pubkey;
        const char* plaintext;
        size_t plaintext_len;
    } encrypt_ctx;
    
    encrypt_ctx ctx = {
        .sender_privkey = &sender.privkey,
        .recipient_pubkey = &recipient.pubkey,
        .plaintext = test_message,
        .plaintext_len = strlen(test_message)
    };
    
    void nip44_encrypt_wrapper(void* data) {
        encrypt_ctx* ctx = (encrypt_ctx*)data;
        char* ciphertext;
        nostr_nip44_encrypt(ctx->sender_privkey, ctx->recipient_pubkey,
                           ctx->plaintext, ctx->plaintext_len, &ciphertext);
        if (ciphertext) free(ciphertext);
    }
    
    benchmark_run("nip44_encrypt", nip44_encrypt_wrapper, &ctx, 1000, &result);
    add_measurement(report, "nip44_encrypt", result.avg_ns);
    
    void nip04_encrypt_wrapper(void* data) {
        encrypt_ctx* ctx = (encrypt_ctx*)data;
        char* ciphertext;
        nostr_nip04_encrypt(ctx->sender_privkey, ctx->recipient_pubkey,
                           ctx->plaintext, &ciphertext);
        if (ciphertext) free(ciphertext);
    }
    
    benchmark_run("nip04_encrypt", nip04_encrypt_wrapper, &ctx, 1000, &result);
    add_measurement(report, "nip04_encrypt", result.avg_ns);
    
    nostr_event_destroy(event);
    nostr_keypair_destroy(&sender);
    nostr_keypair_destroy(&recipient);
}

static void print_regression_report(const regression_report* report) {
    printf("Performance Regression Test Report\n");
    printf("==================================\n\n");
    
    if (report->count == 0) {
        printf("No baseline data available.\n");
        return;
    }
    
    printf("%-30s %12s %12s %8s %10s\n", "Test", "Baseline", "Current", "Ratio", "Status");
    printf("%-30s %12s %12s %8s %10s\n", "----", "--------", "-------", "-----", "------");
    
    for (int i = 0; i < report->count; i++) {
        const regression_result* test = &report->tests[i];
        
        if (test->baseline_ns == 0.0) {
            printf("%-30s %12s %12.2f %8s %10s\n", 
                   test->name, "N/A", test->current_ns, "N/A", "NEW");
        } else {
            const char* status;
            if (test->regression) {
                status = "REGRESS";
            } else if (test->ratio < 0.9) {
                status = "IMPROVE";
            } else {
                status = "OK";
            }
            
            printf("%-30s %12.2f %12.2f %8.2fx %10s\n",
                   test->name, test->baseline_ns, test->current_ns, test->ratio, status);
        }
    }
    
    printf("\nSummary:\n");
    printf("--------\n");
    printf("Total tests: %d\n", report->count);
    printf("Regressions: %d\n", report->regressions);
    printf("Improvements: %d\n", report->improvements);
    
    if (report->regressions > 0) {
        printf("\nWARNING: %d performance regression(s) detected!\n", report->regressions);
        printf("Tests with >%.1fx performance degradation are considered regressions.\n", REGRESSION_THRESHOLD);
    } else {
        printf("\nNo performance regressions detected.\n");
    }
}

int main(int argc, char* argv[]) {
    printf("libnostr-c Performance Regression Test\n");
    printf("======================================\n\n");
    
    if (nostr_init() != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c\n");
        return 1;
    }
    
    regression_report report = {0};
    const char* baseline_file = "performance_baseline.txt";
    
    int save_baseline_flag = 0;
    if (argc > 1 && strcmp(argv[1], "--save-baseline") == 0) {
        save_baseline_flag = 1;
        printf("Running in baseline save mode...\n\n");
    } else {
        load_baseline(baseline_file, &report);
    }
    
    printf("Running regression benchmarks...\n");
    run_regression_benchmarks(&report);
    printf("Benchmarks complete.\n\n");
    
    if (save_baseline_flag) {
        save_baseline(baseline_file, &report);
    } else {
        print_regression_report(&report);
    }
    
    nostr_cleanup();
    return (report.regressions > 0) ? 1 : 0;
}