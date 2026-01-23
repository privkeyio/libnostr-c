#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "nostr.h"

static void bytes_to_hex(const uint8_t* bytes, size_t len, char* hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

static void test_nip06_vector1() {
    printf("Testing NIP-06 vector 1 (12 words)...\n");

    const char* mnemonic = "leader monkey parrot ring guide accident before fence cannon height naive bean";
    const char* expected_privkey = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
    const char* expected_pubkey = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";

    nostr_error_t err = nostr_mnemonic_validate(mnemonic);
    assert(err == NOSTR_OK);

    nostr_keypair keypair;
    err = nostr_mnemonic_to_keypair(mnemonic, NULL, 0, &keypair);
    assert(err == NOSTR_OK);

    char privkey_hex[65];
    char pubkey_hex[65];
    bytes_to_hex(keypair.privkey.data, 32, privkey_hex);
    bytes_to_hex(keypair.pubkey.data, 32, pubkey_hex);

    assert(strcmp(privkey_hex, expected_privkey) == 0);
    assert(strcmp(pubkey_hex, expected_pubkey) == 0);

    printf("  Vector 1: PASS\n");
}

static void test_nip06_vector2() {
    printf("Testing NIP-06 vector 2 (24 words)...\n");

    const char* mnemonic = "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade";
    const char* expected_privkey = "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add";
    const char* expected_pubkey = "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573";

    nostr_error_t err = nostr_mnemonic_validate(mnemonic);
    assert(err == NOSTR_OK);

    nostr_keypair keypair;
    err = nostr_mnemonic_to_keypair(mnemonic, NULL, 0, &keypair);
    assert(err == NOSTR_OK);

    char privkey_hex[65];
    char pubkey_hex[65];
    bytes_to_hex(keypair.privkey.data, 32, privkey_hex);
    bytes_to_hex(keypair.pubkey.data, 32, pubkey_hex);

    assert(strcmp(privkey_hex, expected_privkey) == 0);
    assert(strcmp(pubkey_hex, expected_pubkey) == 0);

    printf("  Vector 2: PASS\n");
}

static void test_mnemonic_generation() {
    printf("Testing mnemonic generation...\n");

    char mnemonic12[256];
    nostr_error_t err = nostr_mnemonic_generate(12, mnemonic12, sizeof(mnemonic12));
    assert(err == NOSTR_OK);

    err = nostr_mnemonic_validate(mnemonic12);
    assert(err == NOSTR_OK);

    char mnemonic24[512];
    err = nostr_mnemonic_generate(24, mnemonic24, sizeof(mnemonic24));
    assert(err == NOSTR_OK);

    err = nostr_mnemonic_validate(mnemonic24);
    assert(err == NOSTR_OK);

    nostr_keypair keypair;
    err = nostr_mnemonic_to_keypair(mnemonic12, NULL, 0, &keypair);
    assert(err == NOSTR_OK);
    assert(keypair.initialized == 1);

    printf("  Mnemonic generation: PASS\n");
}

static void test_invalid_mnemonic() {
    printf("Testing invalid mnemonic handling...\n");

    nostr_error_t err = nostr_mnemonic_validate("invalid mnemonic words here");
    assert(err == NOSTR_ERR_INVALID_PARAM);

    err = nostr_mnemonic_validate("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon");
    assert(err == NOSTR_ERR_INVALID_PARAM);

    err = nostr_mnemonic_validate("");
    assert(err == NOSTR_ERR_INVALID_PARAM);

    err = nostr_mnemonic_validate(NULL);
    assert(err == NOSTR_ERR_INVALID_PARAM);

    printf("  Invalid mnemonic handling: PASS\n");
}

static void test_passphrase() {
    printf("Testing passphrase support...\n");

    const char* mnemonic = "leader monkey parrot ring guide accident before fence cannon height naive bean";

    nostr_keypair keypair_no_pass;
    nostr_keypair keypair_with_pass;

    nostr_error_t err = nostr_mnemonic_to_keypair(mnemonic, NULL, 0, &keypair_no_pass);
    assert(err == NOSTR_OK);

    err = nostr_mnemonic_to_keypair(mnemonic, "test passphrase", 0, &keypair_with_pass);
    assert(err == NOSTR_OK);

    assert(memcmp(keypair_no_pass.privkey.data, keypair_with_pass.privkey.data, 32) != 0);
    printf("  Passphrase support: PASS\n");
}

static void test_account_index() {
    printf("Testing account index support...\n");

    const char* mnemonic = "leader monkey parrot ring guide accident before fence cannon height naive bean";

    nostr_keypair keypair0;
    nostr_keypair keypair1;

    nostr_error_t err = nostr_mnemonic_to_keypair(mnemonic, NULL, 0, &keypair0);
    assert(err == NOSTR_OK);

    err = nostr_mnemonic_to_keypair(mnemonic, NULL, 1, &keypair1);
    assert(err == NOSTR_OK);

    assert(memcmp(keypair0.privkey.data, keypair1.privkey.data, 32) != 0);
    printf("  Account index support: PASS\n");
}

int main() {
    setbuf(stdout, NULL);
    printf("=== NIP-06 Mnemonic Key Derivation Tests ===\n\n");

    nostr_error_t err = nostr_init();
    if (err != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c: %d\n", err);
        return 1;
    }

    test_nip06_vector1();
    test_nip06_vector2();
    test_mnemonic_generation();
    test_invalid_mnemonic();
    test_passphrase();
    test_account_index();

    printf("=== All NIP-06 tests passed! ===\n");

    nostr_cleanup();
    return 0;
}
