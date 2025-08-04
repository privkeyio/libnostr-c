#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "nostr.h"

int main(void)
{
    printf("Basic Event Creation Example\n");
    printf("============================\n\n");
    
    if (nostr_init() != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c\n");
        return 1;
    }
    
    nostr_privkey privkey;
    nostr_key pubkey;
    
    if (nostr_key_generate(&privkey, &pubkey) != NOSTR_OK) {
        fprintf(stderr, "Failed to generate keypair\n");
        nostr_cleanup();
        return 1;
    }
    
    char pubkey_hex[65];
    char npub[100];
    nostr_key_to_hex(&pubkey, pubkey_hex, sizeof(pubkey_hex));
    nostr_key_to_bech32(&pubkey, "npub", npub, sizeof(npub));
    
    printf("Generated new keypair:\n");
    printf("  Public key (hex): %s\n", pubkey_hex);
    printf("  Public key (npub): %s\n\n", npub);
    
    nostr_event* event;
    if (nostr_event_create(&event) != NOSTR_OK) {
        fprintf(stderr, "Failed to create event\n");
        nostr_cleanup();
        return 1;
    }
    
    event->kind = 1;
    event->created_at = time(NULL);
    event->pubkey = pubkey;
    
    nostr_event_set_content(event, "Hello, Nostr! This is my first event created with libnostr-c.");
    
    const char* p_tag[] = {"p", pubkey_hex, "wss://relay.damus.io", "self"};
    nostr_event_add_tag(event, p_tag, 4);
    
    const char* t_tag[] = {"t", "nostr", "libnostr-c"};
    nostr_event_add_tag(event, t_tag, 3);
    
    if (nostr_event_compute_id(event) != NOSTR_OK) {
        fprintf(stderr, "Failed to compute event ID\n");
        nostr_event_destroy(event);
        nostr_cleanup();
        return 1;
    }
    
    if (nostr_event_sign(event, &privkey) != NOSTR_OK) {
        fprintf(stderr, "Failed to sign event\n");
        nostr_event_destroy(event);
        nostr_cleanup();
        return 1;
    }
    
    printf("Created event:\n");
    printf("  Kind: %d\n", event->kind);
    printf("  Created at: %ld\n", (long)event->created_at);
    printf("  Content: %s\n", event->content);
    printf("  Tags: %zu\n", event->tags_count);
    
    char event_id_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&event_id_hex[i * 2], "%02x", event->id[i]);
    }
    event_id_hex[64] = '\0';
    printf("  Event ID: %s\n", event_id_hex);
    
    if (nostr_event_verify(event) == NOSTR_OK) {
        printf("  Signature: Valid\n");
    } else {
        printf("  Signature: Invalid\n");
    }
    
    char* json;
    if (nostr_event_to_json(event, &json) == NOSTR_OK) {
        printf("\nSerialized JSON:\n%s\n", json);
        free(json);
    }
    
    nostr_event_destroy(event);
    nostr_cleanup();
    
    printf("\nSuccess: Example completed successfully!\n");
    return 0;
}