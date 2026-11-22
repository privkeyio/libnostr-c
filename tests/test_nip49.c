#include <stdio.h>
#include <string.h>
#include "../include/nostr.h"

#include "unity.h"

void test_ncryptsec_encrypt_decrypt(void)
{
    nostr_init();

    nostr_privkey original_privkey;
    nostr_key pubkey;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_generate(&original_privkey, &pubkey));

    char ncryptsec[256];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_ncryptsec_encrypt(&original_privkey, "testpassword123", 16, ncryptsec, sizeof(ncryptsec)));

    TEST_ASSERT_TRUE(strncmp(ncryptsec, "ncryptsec1", 10) == 0);
    TEST_ASSERT_TRUE(strlen(ncryptsec) > 100);

    nostr_privkey decrypted_privkey;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_ncryptsec_decrypt(ncryptsec, "testpassword123", &decrypted_privkey));

    TEST_ASSERT_EQUAL_MEMORY(original_privkey.data, decrypted_privkey.data, NOSTR_PRIVKEY_SIZE);

    secure_wipe(&original_privkey, sizeof(original_privkey));
    secure_wipe(&decrypted_privkey, sizeof(decrypted_privkey));

}

void test_ncryptsec_wrong_password(void)
{
    nostr_init();

    nostr_privkey original_privkey;
    nostr_key pubkey;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_generate(&original_privkey, &pubkey));

    char ncryptsec[256];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_ncryptsec_encrypt(&original_privkey, "correctpassword", 16, ncryptsec, sizeof(ncryptsec)));

    nostr_privkey decrypted_privkey;
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_SIGNATURE, nostr_ncryptsec_decrypt(ncryptsec, "wrongpassword", &decrypted_privkey));

    secure_wipe(&original_privkey, sizeof(original_privkey));

}

void test_ncryptsec_validate(void)
{
    nostr_init();

    nostr_privkey privkey;
    nostr_key pubkey;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_generate(&privkey, &pubkey));

    char ncryptsec[256];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_ncryptsec_encrypt(&privkey, "password", 16, ncryptsec, sizeof(ncryptsec)));

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_ncryptsec_validate(ncryptsec));

    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, nostr_ncryptsec_validate("nsec1abcdef"));
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, nostr_ncryptsec_validate("ncryptsec1invalid"));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_ncryptsec_validate(NULL));

    secure_wipe(&privkey, sizeof(privkey));

}

void test_ncryptsec_known_vector(void)
{
    nostr_init();

    /* gitleaks:allow - NIP-49 official test vector from spec */
    const char *test_ncryptsec = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
    /* gitleaks:allow - NIP-49 official test vector from spec */
    const char *expected_privkey_hex = "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683";

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_ncryptsec_validate(test_ncryptsec));

    nostr_privkey decrypted_privkey;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_ncryptsec_decrypt(test_ncryptsec, "nostr", &decrypted_privkey));

    char decrypted_hex[65];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_privkey_to_hex(&decrypted_privkey, decrypted_hex, sizeof(decrypted_hex)));

    TEST_ASSERT_EQUAL_STRING(expected_privkey_hex, decrypted_hex);

    secure_wipe(&decrypted_privkey, sizeof(decrypted_privkey));

}

void test_ncryptsec_different_log_n(void)
{
    nostr_init();

    nostr_privkey original_privkey;
    nostr_key pubkey;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_generate(&original_privkey, &pubkey));

    char ncryptsec[256];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_ncryptsec_encrypt(&original_privkey, "password", 18, ncryptsec, sizeof(ncryptsec)));

    nostr_privkey decrypted_privkey;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_ncryptsec_decrypt(ncryptsec, "password", &decrypted_privkey));

    TEST_ASSERT_EQUAL_MEMORY(original_privkey.data, decrypted_privkey.data, NOSTR_PRIVKEY_SIZE);

    secure_wipe(&original_privkey, sizeof(original_privkey));
    secure_wipe(&decrypted_privkey, sizeof(decrypted_privkey));

}

void test_ncryptsec_invalid_params(void)
{
    nostr_init();

    nostr_privkey privkey;
    nostr_key pubkey;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_generate(&privkey, &pubkey));

    char ncryptsec[256];

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_ncryptsec_encrypt(NULL, "password", 16, ncryptsec, sizeof(ncryptsec)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_ncryptsec_encrypt(&privkey, NULL, 16, ncryptsec, sizeof(ncryptsec)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_ncryptsec_encrypt(&privkey, "password", 16, NULL, sizeof(ncryptsec)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_ncryptsec_encrypt(&privkey, "password", 15, ncryptsec, sizeof(ncryptsec)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_ncryptsec_encrypt(&privkey, "password", 23, ncryptsec, sizeof(ncryptsec)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_ncryptsec_encrypt(&privkey, "password", 16, ncryptsec, 50));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_ncryptsec_encrypt(&privkey, "", 16, ncryptsec, sizeof(ncryptsec)));

    nostr_privkey decrypted;
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_ncryptsec_decrypt(NULL, "password", &decrypted));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_ncryptsec_decrypt("ncryptsec1...", NULL, &decrypted));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_ncryptsec_decrypt("ncryptsec1...", "password", NULL));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_ncryptsec_decrypt("ncryptsec1...", "", &decrypted));

    secure_wipe(&privkey, sizeof(privkey));

}

void test_ncryptsec_unicode_password(void)
{
    nostr_init();

    nostr_privkey original_privkey;
    nostr_key pubkey;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_generate(&original_privkey, &pubkey));

    char ncryptsec[256];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_ncryptsec_encrypt(&original_privkey, "пароль密码🔐", 16, ncryptsec, sizeof(ncryptsec)));

    nostr_privkey decrypted_privkey;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_ncryptsec_decrypt(ncryptsec, "пароль密码🔐", &decrypted_privkey));

    TEST_ASSERT_EQUAL_MEMORY(original_privkey.data, decrypted_privkey.data, NOSTR_PRIVKEY_SIZE);

    secure_wipe(&original_privkey, sizeof(original_privkey));
    secure_wipe(&decrypted_privkey, sizeof(decrypted_privkey));

}

void run_nip49_tests(void)
{
    printf("Running NIP-49 tests...\n");

    RUN_TEST(test_ncryptsec_encrypt_decrypt);
    RUN_TEST(test_ncryptsec_wrong_password);
    RUN_TEST(test_ncryptsec_validate);
    RUN_TEST(test_ncryptsec_known_vector);
    RUN_TEST(test_ncryptsec_different_log_n);
    RUN_TEST(test_ncryptsec_invalid_params);
    RUN_TEST(test_ncryptsec_unicode_password);
}

#ifndef TEST_RUNNER_INCLUDED
void setUp(void) {}
void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    run_nip49_tests();
    return UNITY_END();
}
#endif
