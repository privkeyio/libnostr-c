#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#define sleep(x) Sleep((x) * 1000)
#endif
#include "nostr.h"

static volatile int event_published = 0;

void relay_state_callback(nostr_relay* relay, nostr_relay_state state, void* user_data) {
    switch (state) {
        case NOSTR_RELAY_CONNECTED:
            printf("Success: Connected to relay: %s\n", relay->url);
            break;
        case NOSTR_RELAY_DISCONNECTED:
            printf("Disconnected from relay: %s\n", relay->url);
            break;
        case NOSTR_RELAY_ERROR:
            printf("Connection error to relay: %s\n", relay->url);
            break;
        default:
            break;
    }
}

void message_callback(const char* message_type, const char* data, void* user_data) {
    printf("Received %s message: %s\n", message_type, data);
    if (strcmp(message_type, "OK") == 0) {
        event_published = 1;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s \"<your message>\"\n", argv[0]);
        printf("Example: %s \"Hello, Nostr! Testing libnostr-c.\"\n", argv[0]);
        return 1;
    }
    
    const char* content = argv[1];
    
    printf("Publishing Note Example\n");
    printf("=======================\n\n");
    
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
    
    char npub[100];
    nostr_key_to_bech32(&pubkey, "npub", npub, sizeof(npub));
    printf("Publishing as: %s\n", npub);
    
    nostr_event* event;
    if (nostr_event_create(&event) != NOSTR_OK) {
        fprintf(stderr, "Failed to create event\n");
        nostr_cleanup();
        return 1;
    }
    
    event->kind = 1;
    event->created_at = time(NULL);
    event->pubkey = pubkey;
    
    nostr_event_set_content(event, content);
    
    const char* t_tag[] = {"t", "libnostr-c"};
    nostr_event_add_tag(event, t_tag, 2);
    
    const char* client_tag[] = {"client", "libnostr-c-example"};
    nostr_event_add_tag(event, client_tag, 2);
    
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
    
    char event_id_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&event_id_hex[i * 2], "%02x", event->id[i]);
    }
    event_id_hex[64] = '\0';
    
    printf("Created event ID: %s\n", event_id_hex);
    printf("Content: %s\n\n", event->content);
    
    const char* relay_urls[] = {
        "wss://relay.damus.io",
        "wss://nostr.band",
        "wss://relay.nostr.band"
    };
    int num_relays = sizeof(relay_urls) / sizeof(relay_urls[0]);
    
    printf("Connecting to relays...\n");
    
    #define MAX_RELAYS 10
    nostr_relay* relays[MAX_RELAYS];
    int connected_count = 0;
    
    for (int i = 0; i < num_relays; i++) {
        if (nostr_relay_create(&relays[i], relay_urls[i]) == NOSTR_OK) {
            nostr_relay_set_message_callback(relays[i], message_callback, NULL);
            
            if (nostr_relay_connect(relays[i], relay_state_callback, NULL) == NOSTR_OK) {
                printf("Connecting to %s...\n", relay_urls[i]);
            } else {
                printf("Failed to initiate connection to %s\n", relay_urls[i]);
                nostr_relay_destroy(relays[i]);
                relays[i] = NULL;
            }
        } else {
            printf("Failed to create relay for %s\n", relay_urls[i]);
            relays[i] = NULL;
        }
    }
    
    printf("Waiting for connections...\n");
    sleep(3);
    
    for (int i = 0; i < num_relays; i++) {
        if (relays[i] && relays[i]->state == NOSTR_RELAY_CONNECTED) {
            connected_count++;
        }
    }
    
    printf("Connected to %d/%d relays\n\n", connected_count, num_relays);
    
    if (connected_count == 0) {
        printf("No relay connections available, cannot publish event\n");
    } else {
        printf("Publishing event to connected relays...\n");
        
        for (int i = 0; i < num_relays; i++) {
            if (relays[i] && relays[i]->state == NOSTR_RELAY_CONNECTED) {
                if (nostr_publish_event(relays[i], event) == NOSTR_OK) {
                    printf("Success: Event sent to %s\n", relay_urls[i]);
                } else {
                    printf("Error: Failed to send event to %s\n", relay_urls[i]);
                }
            }
        }
        
        printf("\nWaiting for confirmations...\n");
        
        int timeout = 0;
        while (!event_published && timeout < 10) {
            sleep(1);
            timeout++;
        }
        
        if (event_published) {
            printf("Success: Event publication confirmed!\n");
            printf("\nYour note has been published to Nostr!\n");
            printf("Event ID: %s\n", event_id_hex);
            printf("Author: %s\n", npub);
        } else {
            printf("Error: No publication confirmation received\n");
        }
    }
    
    printf("\nDisconnecting from relays...\n");
    for (int i = 0; i < num_relays; i++) {
        if (relays[i]) {
            if (relays[i]->state == NOSTR_RELAY_CONNECTED) {
                nostr_relay_disconnect(relays[i]);
            }
            nostr_relay_destroy(relays[i]);
        }
    }
    
    nostr_event_destroy(event);
    nostr_cleanup();
    
    printf("Success: Example completed!\n");
    return 0;
}