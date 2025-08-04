#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "nostr.h"

int main() {
    printf("HD Key Integration Test\n");
    printf("======================\n\n");
    
    nostr_error_t err = nostr_init();
    assert(err == NOSTR_OK);
    
    const char* test_seed = "integration test seed for HD keys";
    nostr_hd_key master;
    err = nostr_hd_key_from_seed((const uint8_t*)test_seed, strlen(test_seed), &master);
    assert(err == NOSTR_OK);
    printf("Success: Generated master key from seed\n");
    
    nostr_hd_key derived;
    err = nostr_hd_key_derive_path(&master, NOSTR_HD_PATH_STANDARD, &derived);
    assert(err == NOSTR_OK);
    printf("Success: Derived standard Nostr key path\n");
    
    nostr_keypair kp;
    err = nostr_hd_key_to_keypair(&derived, &kp);
    assert(err == NOSTR_OK);
    assert(kp.initialized == 1);
    printf("Success: Converted HD key to keypair\n");
    
    nostr_event* event;
    err = nostr_event_create(&event);
    assert(err == NOSTR_OK);
    
    event->kind = 1;
    event->created_at = time(NULL);
    memcpy(&event->pubkey, &kp.pubkey, sizeof(nostr_key));
    err = nostr_event_set_content(event, "Test message from HD-derived key");
    assert(err == NOSTR_OK);
    
    err = nostr_event_compute_id(event);
    assert(err == NOSTR_OK);
    printf("Success: Computed event ID\n");
    
    err = nostr_event_sign(event, &kp.privkey);
    assert(err == NOSTR_OK);
    printf("Success: Signed event with HD-derived key\n");
    
    err = nostr_event_verify(event);
    assert(err == NOSTR_OK);
    printf("Success: Verified event signature\n");
    
    char hex[65];
    nostr_key_to_hex(&kp.pubkey, hex, sizeof(hex));
    printf("\nHD-derived public key: %s\n", hex);
    
    char bech32[256];
    err = nostr_key_to_bech32(&kp.pubkey, "npub", bech32, sizeof(bech32));
    if (err == NOSTR_OK) {
        printf("HD-derived npub: %s\n", bech32);
    }
    
    nostr_event_destroy(event);
    nostr_cleanup();
    
    printf("\nSuccess: HD key integration test passed!\n");
    return 0;
}