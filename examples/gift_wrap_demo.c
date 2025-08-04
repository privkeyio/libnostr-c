#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/nostr.h"

void print_hex(const char* label, const uint8_t* data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[])
{
    nostr_error_t err;
    
    printf("=== NIP-59 Gift Wrap Demo ===\n\n");
    
    // Initialize library
    err = nostr_init();
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize: %s\n", nostr_error_string(err));
        return 1;
    }
    
    // Generate author keypair
    nostr_privkey author_privkey;
    nostr_key author_pubkey;
    err = nostr_key_generate(&author_privkey, &author_pubkey);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to generate author keys: %s\n", nostr_error_string(err));
        return 1;
    }
    
    printf("Author keys generated:\n");
    print_hex("  Private", author_privkey.data, 32);
    print_hex("  Public ", author_pubkey.data, 32);
    printf("\n");
    
    // Generate recipient keypair
    nostr_privkey recipient_privkey;
    nostr_key recipient_pubkey;
    err = nostr_key_generate(&recipient_privkey, &recipient_pubkey);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to generate recipient keys: %s\n", nostr_error_string(err));
        return 1;
    }
    
    printf("Recipient keys generated:\n");
    print_hex("  Public", recipient_pubkey.data, 32);
    printf("\n");
    
    // Create a sensitive event (e.g., a private article)
    nostr_event* article = NULL;
    err = nostr_event_create(&article);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to create event: %s\n", nostr_error_string(err));
        return 1;
    }
    
    // Set event properties
    article->kind = 30023;  // Long-form content
    article->created_at = time(NULL);
    memcpy(&article->pubkey, &author_pubkey, sizeof(nostr_key));
    
    // Set content
    const char* content = "This is a confidential article that should only be readable by the intended recipient.";
    err = nostr_event_set_content(article, content);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to set content: %s\n", nostr_error_string(err));
        nostr_event_destroy(article);
        return 1;
    }
    
    // Add metadata tags
    const char* title_tag[2] = {"title", "Confidential Report"};
    const char* summary_tag[2] = {"summary", "For your eyes only"};
    const char* published_tag[2] = {"published_at", "1234567890"};
    
    nostr_event_add_tag(article, title_tag, 2);
    nostr_event_add_tag(article, summary_tag, 2);
    nostr_event_add_tag(article, published_tag, 2);
    
    // Sign the event
    err = nostr_event_compute_id(article);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to compute ID: %s\n", nostr_error_string(err));
        nostr_event_destroy(article);
        return 1;
    }
    
    err = nostr_event_sign(article, &author_privkey);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to sign: %s\n", nostr_error_string(err));
        nostr_event_destroy(article);
        return 1;
    }
    
    printf("Original event created:\n");
    printf("  Kind: %d\n", article->kind);
    printf("  Created at: %ld\n", article->created_at);
    printf("  Content: %s\n", article->content);
    printf("  Tags: %zu\n", article->tags_count);
    for (size_t i = 0; i < article->tags_count; i++) {
        printf("    [%s, %s]\n", article->tags[i].values[0], article->tags[i].values[1]);
    }
    printf("\n");
    
    // Wrap the event using NIP-59
    nostr_event* gift_wrap = NULL;
    err = nostr_nip59_wrap_event(&gift_wrap, article, &author_privkey, &recipient_pubkey);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to wrap event: %s\n", nostr_error_string(err));
        nostr_event_destroy(article);
        return 1;
    }
    
    printf("Gift wrap created:\n");
    printf("  Kind: %d (should be 1059)\n", gift_wrap->kind);
    printf("  Created at: %ld (randomized)\n", gift_wrap->created_at);
    print_hex("  Ephemeral pubkey", gift_wrap->pubkey.data, 32);
    printf("  Content length: %zu bytes (encrypted)\n", strlen(gift_wrap->content));
    printf("  Visible tags: %zu\n", gift_wrap->tags_count);
    for (size_t i = 0; i < gift_wrap->tags_count; i++) {
        printf("    [%s, ...]\n", gift_wrap->tags[i].values[0]);
    }
    printf("\n");
    
    // Simulate sending to recipient...
    printf("--- Simulating network transmission ---\n\n");
    
    // Recipient unwraps the gift
    nostr_event* unwrapped = NULL;
    nostr_key verified_author;
    
    err = nostr_nip59_unwrap_event(gift_wrap, &recipient_privkey, &unwrapped, &verified_author);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to unwrap: %s\n", nostr_error_string(err));
        nostr_event_destroy(article);
        nostr_event_destroy(gift_wrap);
        return 1;
    }
    
    printf("Gift wrap unwrapped successfully:\n");
    printf("  Kind: %d (matches: %s)\n", unwrapped->kind, 
           unwrapped->kind == article->kind ? "yes" : "no");
    printf("  Content: %s\n", unwrapped->content);
    printf("  Created at: %ld (matches: %s)\n", unwrapped->created_at,
           unwrapped->created_at == article->created_at ? "yes" : "no");
    print_hex("  Verified author", verified_author.data, 32);
    printf("  Author matches: %s\n", 
           memcmp(&verified_author, &author_pubkey, sizeof(nostr_key)) == 0 ? "yes" : "no");
    printf("  Tags recovered: %zu\n", unwrapped->tags_count);
    for (size_t i = 0; i < unwrapped->tags_count; i++) {
        printf("    [%s, %s]\n", unwrapped->tags[i].values[0], unwrapped->tags[i].values[1]);
    }
    printf("\n");
    
    // Try to unwrap with wrong key (should fail)
    nostr_privkey wrong_privkey;
    nostr_key wrong_pubkey;
    nostr_key_generate(&wrong_privkey, &wrong_pubkey);
    
    nostr_event* fail_unwrap = NULL;
    err = nostr_nip59_unwrap_event(gift_wrap, &wrong_privkey, &fail_unwrap, NULL);
    printf("Unwrap with wrong key: %s (expected failure)\n", 
           err != NOSTR_OK ? "Failed as expected" : "ERROR: Should have failed!");
    
    // Cleanup
    nostr_event_destroy(article);
    nostr_event_destroy(gift_wrap);
    nostr_event_destroy(unwrapped);
    
    printf("\nSuccess: Gift wrap demo completed successfully!\n");
    
    return 0;
}