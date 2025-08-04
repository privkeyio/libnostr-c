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
#include <signal.h>
#include "nostr.h"

static volatile int running = 1;
static int event_count = 0;

void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    running = 0;
}

void relay_state_callback(nostr_relay* relay, nostr_relay_state state, void* user_data) {
    switch (state) {
        case NOSTR_RELAY_CONNECTED:
            printf("Success: Connected to %s\n", relay->url);
            break;
        case NOSTR_RELAY_DISCONNECTED:
            printf("Disconnected from %s\n", relay->url);
            break;
        case NOSTR_RELAY_ERROR:
            printf("Connection error to %s\n", relay->url);
            break;
        default:
            break;
    }
}

void message_callback(const char* message_type, const char* data, void* user_data) {
    if (strcmp(message_type, "EOSE") == 0) {
        printf("End of stored events received\n");
    } else if (strcmp(message_type, "NOTICE") == 0) {
        printf("Notice: %s\n", data);
    }
}

void event_callback(const nostr_event* event, void* user_data) {
    event_count++;
    
    time_t created_at = (time_t)event->created_at;
    struct tm* timeinfo = localtime(&created_at);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);
    
    char pubkey_short[13];
    char pubkey_hex[65];
    nostr_key_to_hex(&event->pubkey, pubkey_hex, sizeof(pubkey_hex));
    strncpy(pubkey_short, pubkey_hex, 12);
    pubkey_short[12] = '\0';
    
    char* content_display = event->content ? event->content : "(no content)";
    int content_len = strlen(content_display);
    
    printf("[%s] Kind %d from %s...\n", time_str, event->kind, pubkey_short);
    
    if (content_len > 80) {
        printf("  %.77s...\n", content_display);
    } else {
        printf("  %s\n", content_display);
    }
    
    if (event->tags_count > 0) {
        printf("  Tags: ");
        for (size_t i = 0; i < event->tags_count && i < 3; i++) {
            if (event->tags[i].count > 0) {
                printf("#%s ", event->tags[i].values[0]);
            }
        }
        if (event->tags_count > 3) {
            printf("(+%zu more)", event->tags_count - 3);
        }
        printf("\n");
    }
    
    printf("\n");
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("Event Subscription Example\n");
    printf("==========================\n\n");
    
    if (nostr_init() != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c\n");
        return 1;
    }
    
    const char* relay_url = "wss://relay.damus.io";
    if (argc > 1) {
        relay_url = argv[1];
    }
    
    printf("Connecting to relay: %s\n", relay_url);
    
    nostr_relay* relay;
    if (nostr_relay_create(&relay, relay_url) != NOSTR_OK) {
        fprintf(stderr, "Failed to create relay\n");
        nostr_cleanup();
        return 1;
    }
    
    nostr_relay_set_message_callback(relay, message_callback, NULL);
    
    if (nostr_relay_connect(relay, relay_state_callback, NULL) != NOSTR_OK) {
        fprintf(stderr, "Failed to connect to relay\n");
        nostr_relay_destroy(relay);
        nostr_cleanup();
        return 1;
    }
    
    printf("Waiting for connection...\n");
    
    int attempts = 0;
    while (running && relay->state != NOSTR_RELAY_CONNECTED && attempts < 10) {
        sleep(1);
        attempts++;
        if (relay->state == NOSTR_RELAY_ERROR) {
            fprintf(stderr, "Connection failed\n");
            break;
        }
    }
    
    if (relay->state != NOSTR_RELAY_CONNECTED) {
        printf("Failed to connect within timeout\n");
        nostr_relay_destroy(relay);
        nostr_cleanup();
        return 1;
    }
    
    printf("\nSubscribing to different types of events...\n\n");
    
    printf("1. Recent text notes (kind 1):\n");
    const char* text_notes_filter = "{"
        "\"kinds\": [1],"
        "\"limit\": 5"
        "}";
    
    if (nostr_subscribe(relay, "text-notes", text_notes_filter, event_callback, NULL) != NOSTR_OK) {
        printf("Failed to subscribe to text notes\n");
    }
    
    sleep(3);
    
    printf("\n2. Metadata events (kind 0):\n");
    const char* metadata_filter = "{"
        "\"kinds\": [0],"
        "\"limit\": 3"
        "}";
    
    if (nostr_subscribe(relay, "metadata", metadata_filter, event_callback, NULL) != NOSTR_OK) {
        printf("Failed to subscribe to metadata\n");
    }
    
    sleep(3);
    
    printf("\n3. Recent events with #nostr tag:\n");
    const char* tagged_filter = "{"
        "\"kinds\": [1],"
        "\"#t\": [\"nostr\"],"
        "\"limit\": 3"
        "}";
    
    if (nostr_subscribe(relay, "tagged", tagged_filter, event_callback, NULL) != NOSTR_OK) {
        printf("Failed to subscribe to tagged events\n");
    }
    
    sleep(3);
    
    printf("\n4. Live stream of new text notes:\n");
    printf("(Press Ctrl+C to stop)\n\n");
    
    time_t now = time(NULL);
    char since_str[32];
    snprintf(since_str, sizeof(since_str), "%ld", (long)now);
    
    char live_filter[256];
    snprintf(live_filter, sizeof(live_filter), 
        "{"
        "\"kinds\": [1],"
        "\"since\": %s"
        "}", since_str);
    
    if (nostr_subscribe(relay, "live", live_filter, event_callback, NULL) != NOSTR_OK) {
        printf("Failed to subscribe to live events\n");
    }
    
    while (running && relay->state == NOSTR_RELAY_CONNECTED) {
        sleep(1);
    }
    
    printf("\nUnsubscribing from all subscriptions...\n");
    nostr_relay_unsubscribe(relay, "text-notes");
    nostr_relay_unsubscribe(relay, "metadata");
    nostr_relay_unsubscribe(relay, "tagged");
    nostr_relay_unsubscribe(relay, "live");
    
    printf("Disconnecting from relay...\n");
    nostr_relay_disconnect(relay);
    nostr_relay_destroy(relay);
    nostr_cleanup();
    
    printf("\nSuccess: Received %d events total\n", event_count);
    printf("Success: Example completed!\n");
    return 0;
}