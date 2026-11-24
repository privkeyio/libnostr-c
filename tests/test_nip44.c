#include "unity.h"
#include "../include/nostr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static nostr_privkey privkey1, privkey2;
static nostr_key pubkey1, pubkey2;

void setUp(void)
{
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_generate(&privkey1, &pubkey1));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_generate(&privkey2, &pubkey2));
}

void tearDown(void)
{
}

/* NIP-44 v2 payload: version (1) + nonce (32) + length prefix (2) + padded
 * plaintext + MAC (32), base64 encoded with padding. */
static size_t expected_ciphertext_len(size_t padded_len)
{
    return ((1 + 32 + 2 + padded_len + 32 + 2) / 3) * 4;
}

static void test_padding(void)
{
    static const struct {
        size_t input_len;
        size_t padded_len;
    } cases[] = {
        /* calc_padded_len vectors from the NIP-44 test vectors, plus 1. 65536
         * is left out: noscrypt caps the padded data at 65535 bytes. */
        {1, 32}, {16, 32}, {32, 32}, {33, 64}, {37, 64}, {45, 64}, {49, 64},
        {64, 64}, {65, 96}, {100, 128}, {111, 128}, {200, 224}, {250, 256},
        {320, 320}, {383, 384}, {384, 384}, {400, 448}, {500, 512}, {512, 512},
        {515, 640}, {700, 768}, {800, 896}, {900, 1024}, {1020, 1024},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char* plaintext = malloc(cases[i].input_len + 1);
        TEST_ASSERT_NOT_NULL(plaintext);
        memset(plaintext, 'a', cases[i].input_len);
        plaintext[cases[i].input_len] = '\0';

        char* ciphertext = NULL;
        TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip44_encrypt(&privkey1, &pubkey2, plaintext, cases[i].input_len, &ciphertext));
        TEST_ASSERT_EQUAL_size_t_MESSAGE(expected_ciphertext_len(cases[i].padded_len), strlen(ciphertext), "ciphertext length for this plaintext length");

        free(ciphertext);
        free(plaintext);
    }
}

/* Payloads made by an independent NIP-44 implementation, checked against the
 * official encrypt_decrypt vectors, for lengths where the padding chunk
 * differs from a power-of-two-below rounding. sec1 = 1 is the sender, sec2 = 2
 * the recipient, and the plaintext is "abc...z" repeated. */
static void test_decrypt_long_spec_payloads(void)
{
    static const struct {
        size_t len;
        const char* payload;
    } cases[] = {
        {400, "AgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fWIWzC5ug7VcFiM57IEhG2a01D6BDiG52clqBsP2GLw7ET9N3RsLU6jT+pLKSokkhmbA7ytwLyJHq16oGeFPez3Ao3+LCBYBM9OogbHxAvtz4BgIeQfC9Wt6x/G2ANnIRSeoZJs1jH7K0tQQ0IHzR41cJUzV1DeIWA973zzdb2Ytp8WQKbho0sCaYY23dZxE3dYhCMOuPsvL8aycfRDQfzjXLSkzlmsbHIihlHzczMg1R7GCBFW8yyIKONAyoM551XwtiLoYM/aZmv2wuV00CsGj/BdNAlUAVfO2qP57jJOGzGz7nWqT5sTi1jBq9D6MJkGXbvXsrdNTl1lMjUU2c0AuqlUYXMYjbZ3c/TwGh+AVKIzu64q7/B5/3H/om0Rz6Z46CwxgrDr+79WP4fHQS0oZqf9QzSjU0K05VZOlHCvPs0UJD5gwNjpvGh9Hhxqb+yvQSOkJTYccPIHIYafkInIEK2YHimIo6nMpp5khU8Bn2w8sVgI9fe9KsHH770kVJouXOprjHZkbQN2Vvonx80TOKXwCoCbkusTNTM6yReJMoXM3zEMWuA5nSTOPB5PiZo2V+2xmvgFe60jvdfprlQxHQObBOXNp4BRJE/lZbJZZobgL2ZAzcrn1pEkIHvg52qS8="},
        {515, "AgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fWxazC5ug7VcFiM57IEhG2a01D6BDiG52clqBsP2GLw7ET9N3RsLU6jT+pLKSokkhmbA7ytwLyJHq16oGeFPez3Ao3+LCBYBM9OogbHxAvtz4BgIeQfC9Wt6x/G2ANnIRSeoZJs1jH7K0tQQ0IHzR41cJUzV1DeIWA973zzdb2Ytp8WQKbho0sCaYY23dZxE3dYhCMOuPsvL8aycfRDQfzjXLSkzlmsbHIihlHzczMg1R7GCBFW8yyIKONAyoM551XwtiLoYM/aZmv2wuV00CsGj/BdNAlUAVfO2qP57jJOGzGz7nWqT5sTi1jBq9D6MJkGXbvXsrdNTl1lMjUU2c0AuqlUYXMYjbZ3c/TwGh+AVKIzu64q7/B5/3H/om0Rz6Z46CwxgrDr+79WP4fHQS0oZqf9QzSjU0K05VZOlHCvPs0UJD5gwNjpvGh9Hhxqb+yvQSOkJTYccPIHIYafkInIEK2YHimIo6nMpp5khU8Bn2w8sVgI9fe9KsHH770kVJouXOprjHZkbQN2Vvonx80TOKNGzFZ9ZewEEgR9nnD+tRJqyRc6HLZf66JYmqiJX3zBUPqWrb9SHNqkKnH/iGJ3S2UvLKAv1LnLUhIf4ofGdyN3em7Mvx2sFIkqTAhbxFcMTeApn+if5mau6aQ3aZgpArxshur20o3dOXauVw/1RSLY0l5v/pRrvbcrGgyC0Zn9AOakkTcvzNUMNDDOdariFLlLeeIklAPE70HLfXMW8W12sO0yx/FfvkiIwWKtDPj6qcxFB/SxkOu6ty0+lz1yVujpdjJNl1AFzaqD48Wi5aVwWxsrGh1JR1jpkULebcZc30L82wTEaSJY4SELCXVnHOCavSNZ1oHQTmGo6ki0/n/W5/WrmSyg/Yup8nRsUa+1U="},
    };
    nostr_privkey recipient;
    nostr_key sender;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_privkey_from_hex("0000000000000000000000000000000000000000000000000000000000000002", &recipient));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", &sender));

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char* plaintext = NULL;
        size_t plaintext_len = 0;
        TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip44_decrypt(&recipient, &sender, cases[i].payload, &plaintext, &plaintext_len));
        TEST_ASSERT_EQUAL_size_t(cases[i].len, plaintext_len);
        for (size_t j = 0; j < plaintext_len; j++) {
            TEST_ASSERT_EQUAL_CHAR('a' + j % 26, plaintext[j]);
        }
        free(plaintext);
    }
}

static void test_basic_encryption(void)
{
    const char* messages[] = {
        "Hello, World!",
        "a",
        "The quick brown fox jumps over the lazy dog",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "Short",
        "This is a longer message that should trigger different padding",
    };

    for (size_t i = 0; i < sizeof(messages) / sizeof(messages[0]); i++) {
        char* ciphertext = NULL;
        char* decrypted = NULL;
        size_t decrypted_len = 0;

        TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip44_encrypt(&privkey1, &pubkey2, messages[i], strlen(messages[i]), &ciphertext));
        TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip44_decrypt(&privkey2, &pubkey1, ciphertext, &decrypted, &decrypted_len));
        TEST_ASSERT_EQUAL_size_t(strlen(messages[i]), decrypted_len);
        TEST_ASSERT_EQUAL_MEMORY(messages[i], decrypted, decrypted_len);

        free(ciphertext);
        free(decrypted);
    }
}

static void test_invalid_operations(void)
{
    char* ciphertext = NULL;
    char* plaintext = NULL;
    size_t plaintext_len = 0;

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip44_encrypt(NULL, &pubkey2, "test", 4, &ciphertext));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip44_encrypt(&privkey1, NULL, "test", 4, &ciphertext));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip44_encrypt(&privkey1, &pubkey2, NULL, 4, &ciphertext));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip44_encrypt(&privkey1, &pubkey2, "test", 4, NULL));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip44_decrypt(&privkey1, &pubkey2, "invalid_base64!", &plaintext, &plaintext_len));
    TEST_ASSERT_EQUAL(NOSTR_ERR_NOT_SUPPORTED, nostr_nip44_decrypt(&privkey1, &pubkey2, "#unsupported", &plaintext, &plaintext_len));
}

static void test_cross_compatibility(void)
{
    const char* message = "Cross-compatibility test message";
    char* ciphertext = NULL;
    char* decrypted = NULL;
    size_t decrypted_len = 0;

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip44_encrypt(&privkey1, &pubkey2, message, strlen(message), &ciphertext));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip44_decrypt(&privkey2, &pubkey1, ciphertext, &decrypted, &decrypted_len));
    TEST_ASSERT_EQUAL_size_t(strlen(message), decrypted_len);
    TEST_ASSERT_EQUAL_MEMORY(message, decrypted, decrypted_len);

    free(ciphertext);
    free(decrypted);
}

int main(void)
{
    if (nostr_init() != NOSTR_OK) {
        fprintf(stderr, "nostr_init failed\n");
        return 1;
    }

    UNITY_BEGIN();
    RUN_TEST(test_padding);
    RUN_TEST(test_decrypt_long_spec_payloads);
    RUN_TEST(test_basic_encryption);
    RUN_TEST(test_invalid_operations);
    RUN_TEST(test_cross_compatibility);
    int failures = UNITY_END();

    nostr_cleanup();
    return failures;
}
