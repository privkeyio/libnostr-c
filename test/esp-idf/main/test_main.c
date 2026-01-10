#include <stdio.h>
#include "nostr.h"

void app_main(void) {
    nostr_keypair keypair;
    nostr_error_t err = nostr_keypair_generate(&keypair);
    if (err == NOSTR_OK) {
        printf("libnostr-c: keypair generated\n");
        nostr_keypair_destroy(&keypair);
    }
}
