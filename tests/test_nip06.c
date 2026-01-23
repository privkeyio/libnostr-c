#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "nostr.h"

static void test_nip06_vector(const char* name, const char* mnemonic,
                              const char* expected_privkey, const char* expected_pubkey)
{
    printf("Testing %s...\n", name);

    assert(nostr_mnemonic_validate(mnemonic) == NOSTR_OK);

    nostr_keypair keypair;
    assert(nostr_mnemonic_to_keypair(mnemonic, NULL, 0, &keypair) == NOSTR_OK);

    char privkey_hex[65];
    char pubkey_hex[65];
    nostr_hex_encode(keypair.privkey.data, 32, privkey_hex);
    nostr_hex_encode(keypair.pubkey.data, 32, pubkey_hex);

    assert(strcmp(privkey_hex, expected_privkey) == 0);
    assert(strcmp(pubkey_hex, expected_pubkey) == 0);

    nostr_keypair_destroy(&keypair);

    printf("  %s: PASS\n", name);
}

static void test_nip06_vector1(void)
{
    test_nip06_vector(
        "NIP-06 vector 1 (12 words)",
        "leader monkey parrot ring guide accident before fence cannon height naive bean",
        "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a",
        "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"
    );
}

static void test_nip06_vector2(void)
{
    test_nip06_vector(
        "NIP-06 vector 2 (24 words)",
        "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade",
        "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add",
        "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573"
    );
}

static void test_mnemonic_generation(void)
{
    printf("Testing mnemonic generation...\n");

    char mnemonic12[256];
    assert(nostr_mnemonic_generate(12, mnemonic12, sizeof(mnemonic12)) == NOSTR_OK);
    assert(nostr_mnemonic_validate(mnemonic12) == NOSTR_OK);

    char mnemonic24[512];
    assert(nostr_mnemonic_generate(24, mnemonic24, sizeof(mnemonic24)) == NOSTR_OK);
    assert(nostr_mnemonic_validate(mnemonic24) == NOSTR_OK);

    nostr_keypair keypair;
    assert(nostr_mnemonic_to_keypair(mnemonic12, NULL, 0, &keypair) == NOSTR_OK);
    assert(keypair.initialized == 1);
    nostr_keypair_destroy(&keypair);

    printf("  Mnemonic generation: PASS\n");
}

static void test_invalid_mnemonic(void)
{
    printf("Testing invalid mnemonic handling...\n");

    assert(nostr_mnemonic_validate("invalid mnemonic words here") == NOSTR_ERR_INVALID_PARAM);
    assert(nostr_mnemonic_validate("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon") == NOSTR_ERR_INVALID_PARAM);
    assert(nostr_mnemonic_validate("") == NOSTR_ERR_INVALID_PARAM);
    assert(nostr_mnemonic_validate(NULL) == NOSTR_ERR_INVALID_PARAM);

    printf("  Invalid mnemonic handling: PASS\n");
}

static void test_passphrase(void)
{
    printf("Testing passphrase support...\n");

    const char* mnemonic = "leader monkey parrot ring guide accident before fence cannon height naive bean";

    nostr_keypair keypair_no_pass;
    nostr_keypair keypair_with_pass;

    assert(nostr_mnemonic_to_keypair(mnemonic, NULL, 0, &keypair_no_pass) == NOSTR_OK);
    assert(nostr_mnemonic_to_keypair(mnemonic, "test passphrase", 0, &keypair_with_pass) == NOSTR_OK);
    assert(memcmp(keypair_no_pass.privkey.data, keypair_with_pass.privkey.data, 32) != 0);

    nostr_keypair_destroy(&keypair_no_pass);
    nostr_keypair_destroy(&keypair_with_pass);

    printf("  Passphrase support: PASS\n");
}

static void test_account_index(void)
{
    printf("Testing account index support...\n");

    const char* mnemonic = "leader monkey parrot ring guide accident before fence cannon height naive bean";

    nostr_keypair keypair0;
    nostr_keypair keypair1;

    assert(nostr_mnemonic_to_keypair(mnemonic, NULL, 0, &keypair0) == NOSTR_OK);
    assert(nostr_mnemonic_to_keypair(mnemonic, NULL, 1, &keypair1) == NOSTR_OK);
    assert(memcmp(keypair0.privkey.data, keypair1.privkey.data, 32) != 0);

    nostr_keypair_destroy(&keypair0);
    nostr_keypair_destroy(&keypair1);

    printf("  Account index support: PASS\n");
}

int main(void)
{
    setbuf(stdout, NULL);
    printf("=== NIP-06 Mnemonic Key Derivation Tests ===\n\n");

    if (nostr_init() != NOSTR_OK) {
        fprintf(stderr, "Failed to initialize libnostr-c\n");
        return 1;
    }

    test_nip06_vector1();
    test_nip06_vector2();
    test_mnemonic_generation();
    test_invalid_mnemonic();
    test_passphrase();
    test_account_index();

    printf("\n=== All NIP-06 tests passed! ===\n");

    nostr_cleanup();
    return 0;
}
