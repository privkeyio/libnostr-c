#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#define sleep(x) Sleep((x) * 1000)
#endif
#include <signal.h>
#include "nostr.h"

static volatile int running = 1;

void signal_handler(int sig) {
    running = 0;
}

void relay_state_callback(nostr_relay* relay, nostr_relay_state state, void* user_data) {
    const char* state_str;
    switch (state) {
        case NOSTR_RELAY_DISCONNECTED:
            state_str = "DISCONNECTED";
            break;
        case NOSTR_RELAY_CONNECTING:
            state_str = "CONNECTING";
            break;
        case NOSTR_RELAY_CONNECTED:
            state_str = "CONNECTED";
            break;
        case NOSTR_RELAY_ERROR:
            state_str = "ERROR";
            break;
        default:
            state_str = "UNKNOWN";
    }
    printf("Relay state changed: %s\n", state_str);
}

void event_callback(const nostr_event* event, void* user_data) {
    printf("Received event: kind=%d, content=%.50s...\n", event->kind, event->content ? event->content : "");
}

int main(void) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Nostr Relay Client Example\n");
    printf("Connecting to wss://relay.damus.io\n");

    if (nostr_init() != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c\n");
        return 1;
    }

    nostr_relay* relay;
    nostr_error_t err = nostr_relay_create(&relay, "wss://relay.damus.io");
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to create relay: %s\n", nostr_error_string(err));
        nostr_cleanup();
        return 1;
    }

    err = nostr_relay_connect(relay, relay_state_callback, NULL);
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to connect to relay: %s\n", nostr_error_string(err));
        nostr_relay_destroy(relay);
        nostr_cleanup();
        return 1;
    }

    printf("Connection initiated. Waiting for connection...\n");
    
    int attempts = 0;
    while (running && relay->state != NOSTR_RELAY_CONNECTED && attempts < 10) {
        sleep(1);
        attempts++;
        if (relay->state == NOSTR_RELAY_ERROR) {
            fprintf(stderr, "Connection failed\n");
            break;
        }
    }

    if (relay->state == NOSTR_RELAY_CONNECTED) {
        printf("Successfully connected! Subscribing to recent events...\n");
        
        char* filter = "{\"kinds\":[1],\"limit\":10}";
        err = nostr_subscribe(relay, "test-sub", filter, event_callback, NULL);
        if (err != NOSTR_OK) {
            fprintf(stderr, "Failed to subscribe: %s\n", nostr_error_string(err));
        } else {
            printf("Subscribed to recent text notes. Press Ctrl+C to exit.\n");
        }

        while (running && relay->state == NOSTR_RELAY_CONNECTED) {
            sleep(1);
        }

        if (relay->state == NOSTR_RELAY_CONNECTED) {
            printf("Unsubscribing...\n");
            nostr_relay_unsubscribe(relay, "test-sub");
        }
    } else {
        printf("Failed to connect within timeout\n");
    }

    printf("Disconnecting...\n");
    nostr_relay_disconnect(relay);
    nostr_relay_destroy(relay);
    nostr_cleanup();

    printf("Client stopped\n");
    return 0;
}