#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../include/nostr.h"
#include "unity.h"

#define TEST_PUBKEY "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"

static void test_nip05_parse_basic(void) {
    char name[65], domain[257];

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_parse("bob@example.com", name, sizeof(name), domain, sizeof(domain)));
    TEST_ASSERT_EQUAL_STRING("bob", name);
    TEST_ASSERT_EQUAL_STRING("example.com", domain);
}

static void test_nip05_parse_root_identifier(void) {
    char name[65], domain[257];

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_parse("_@bob.com", name, sizeof(name), domain, sizeof(domain)));
    TEST_ASSERT_EQUAL_STRING("_", name);
    TEST_ASSERT_EQUAL_STRING("bob.com", domain);
}

static void test_nip05_parse_subdomain(void) {
    char name[65], domain[257];

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_parse("alice@sub.domain.example.com", name, sizeof(name), domain, sizeof(domain)));
    TEST_ASSERT_EQUAL_STRING("alice", name);
    TEST_ASSERT_EQUAL_STRING("sub.domain.example.com", domain);
}

static void test_nip05_parse_with_numbers(void) {
    char name[65], domain[257];

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_parse("user123@site456.io", name, sizeof(name), domain, sizeof(domain)));
    TEST_ASSERT_EQUAL_STRING("user123", name);
    TEST_ASSERT_EQUAL_STRING("site456.io", domain);
}

static void test_nip05_parse_case_insensitive(void) {
    char name[65], domain[257];

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_parse("BOB@EXAMPLE.COM", name, sizeof(name), domain, sizeof(domain)));
    TEST_ASSERT_EQUAL_STRING("bob", name);
    TEST_ASSERT_EQUAL_STRING("example.com", domain);
}

static void test_nip05_parse_invalid_no_at(void) {
    char name[65], domain[257];

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_parse("invalid", name, sizeof(name), domain, sizeof(domain)));
}

static void test_nip05_parse_invalid_no_domain(void) {
    char name[65], domain[257];

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_parse("bob@", name, sizeof(name), domain, sizeof(domain)));
}

static void test_nip05_parse_invalid_no_name(void) {
    char name[65], domain[257];

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_parse("@example.com", name, sizeof(name), domain, sizeof(domain)));
}

static void test_nip05_parse_invalid_domain_no_dot(void) {
    char name[65], domain[257];

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_parse("bob@localhost", name, sizeof(name), domain, sizeof(domain)));
}

static void test_nip05_parse_null_params(void) {
    char name[65], domain[257];

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_parse(NULL, name, sizeof(name), domain, sizeof(domain)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_parse("bob@example.com", NULL, sizeof(name), domain, sizeof(domain)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_parse("bob@example.com", name, sizeof(name), NULL, sizeof(domain)));
}

static void test_nip05_build_url_basic(void) {
    char url[512];

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_build_url("bob", "example.com", url, sizeof(url)));
    TEST_ASSERT_EQUAL_STRING("https://example.com/.well-known/nostr.json?name=bob", url);
}

static void test_nip05_build_url_root(void) {
    char url[512];

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_build_url("_", "bob.com", url, sizeof(url)));
    TEST_ASSERT_EQUAL_STRING("https://bob.com/.well-known/nostr.json?name=_", url);
}

static void test_nip05_build_url_subdomain(void) {
    char url[512];

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_build_url("alice", "sub.example.com", url, sizeof(url)));
    TEST_ASSERT_EQUAL_STRING("https://sub.example.com/.well-known/nostr.json?name=alice", url);
}

static void test_nip05_build_url_null_params(void) {
    char url[512];

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_build_url(NULL, "example.com", url, sizeof(url)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_build_url("bob", NULL, url, sizeof(url)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_build_url("bob", "example.com", NULL, sizeof(url)));
}

static void test_nip05_build_url_buffer_too_small(void) {
    char url[10];

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_build_url("bob", "example.com", url, sizeof(url)));
}

static void test_nip05_parse_response_basic(void) {
    const char* json = "{\"names\":{\"bob\":\"" TEST_PUBKEY "\"}}";
    char pubkey[65];

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_parse_response(json, "bob", pubkey, sizeof(pubkey), NULL, NULL));
    TEST_ASSERT_EQUAL_STRING(TEST_PUBKEY, pubkey);
}

static void test_nip05_parse_response_with_relays(void) {
    const char* json = "{"
        "\"names\":{\"bob\":\"" TEST_PUBKEY "\"},"
        "\"relays\":{\"" TEST_PUBKEY "\":[\"wss://relay.example.com\",\"wss://relay2.example.com\"]}"
        "}";
    char pubkey[65];
    char** relays = NULL;
    size_t relay_count = 0;

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_parse_response(json, "bob", pubkey, sizeof(pubkey), &relays, &relay_count));
    TEST_ASSERT_EQUAL_STRING(TEST_PUBKEY, pubkey);
    TEST_ASSERT_EQUAL(2, relay_count);
    TEST_ASSERT_NOT_NULL(relays);
    TEST_ASSERT_EQUAL_STRING("wss://relay.example.com", relays[0]);
    TEST_ASSERT_EQUAL_STRING("wss://relay2.example.com", relays[1]);

    nostr_nip05_free_relays(relays, relay_count);
}

static void test_nip05_parse_response_name_not_found(void) {
    const char* json = "{\"names\":{\"alice\":\"" TEST_PUBKEY "\"}}";
    char pubkey[65];

    TEST_ASSERT_EQUAL(NOSTR_ERR_NOT_FOUND, nostr_nip05_parse_response(json, "bob", pubkey, sizeof(pubkey), NULL, NULL));
}

static void test_nip05_parse_response_invalid_pubkey_length(void) {
    const char* json = "{\"names\":{\"bob\":\"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07\"}}";
    char pubkey[65];

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_KEY, nostr_nip05_parse_response(json, "bob", pubkey, sizeof(pubkey), NULL, NULL));
}

static void test_nip05_parse_response_no_names(void) {
    const char* json = "{\"relays\":{}}";
    char pubkey[65];

    TEST_ASSERT_EQUAL(NOSTR_ERR_NOT_FOUND, nostr_nip05_parse_response(json, "bob", pubkey, sizeof(pubkey), NULL, NULL));
}

static void test_nip05_parse_response_null_params(void) {
    const char* json = "{\"names\":{\"bob\":\"" TEST_PUBKEY "\"}}";
    char pubkey[65];

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_parse_response(NULL, "bob", pubkey, sizeof(pubkey), NULL, NULL));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_parse_response(json, NULL, pubkey, sizeof(pubkey), NULL, NULL));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_parse_response(json, "bob", NULL, sizeof(pubkey), NULL, NULL));
}

static nostr_error_t mock_http_success(const char* url, char** response, size_t* response_len, void* user_data) {
    (void)url;
    (void)user_data;
    const char* json = "{\"names\":{\"bob\":\"" TEST_PUBKEY "\"}}";
    *response = strdup(json);
    *response_len = strlen(json);
    return NOSTR_OK;
}

static nostr_error_t mock_http_with_relays(const char* url, char** response, size_t* response_len, void* user_data) {
    (void)url;
    (void)user_data;
    const char* json = "{"
        "\"names\":{\"bob\":\"" TEST_PUBKEY "\"},"
        "\"relays\":{\"" TEST_PUBKEY "\":[\"wss://relay.example.com\"]}"
        "}";
    *response = strdup(json);
    *response_len = strlen(json);
    return NOSTR_OK;
}

static nostr_error_t mock_http_fail(const char* url, char** response, size_t* response_len, void* user_data) {
    (void)url;
    (void)user_data;
    *response = NULL;
    *response_len = 0;
    return NOSTR_ERR_CONNECTION;
}

static void test_nip05_verify_success(void) {
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_verify("bob@example.com", TEST_PUBKEY, mock_http_success, NULL, NULL, NULL));
}

static void test_nip05_verify_with_relays(void) {
    char** relays = NULL;
    size_t relay_count = 0;

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_verify("bob@example.com", TEST_PUBKEY, mock_http_with_relays, NULL, &relays, &relay_count));
    TEST_ASSERT_EQUAL(1, relay_count);
    TEST_ASSERT_NOT_NULL(relays);
    TEST_ASSERT_EQUAL_STRING("wss://relay.example.com", relays[0]);

    nostr_nip05_free_relays(relays, relay_count);
}

static void test_nip05_verify_wrong_pubkey(void) {
    const char* wrong_pubkey = "0000000000000000000000000000000000000000000000000000000000000000";

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_KEY, nostr_nip05_verify("bob@example.com", wrong_pubkey, mock_http_success, NULL, NULL, NULL));
}

static void test_nip05_verify_http_failure(void) {
    TEST_ASSERT_EQUAL(NOSTR_ERR_CONNECTION, nostr_nip05_verify("bob@example.com", TEST_PUBKEY, mock_http_fail, NULL, NULL, NULL));
}

static void test_nip05_verify_invalid_identifier(void) {
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_verify("invalid", TEST_PUBKEY, mock_http_success, NULL, NULL, NULL));
}

static void test_nip05_verify_null_params(void) {
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_verify(NULL, TEST_PUBKEY, mock_http_success, NULL, NULL, NULL));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_verify("bob@example.com", NULL, mock_http_success, NULL, NULL, NULL));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_nip05_verify("bob@example.com", TEST_PUBKEY, NULL, NULL, NULL, NULL));
}

static void test_nip05_free_relays_null(void) {
    nostr_nip05_free_relays(NULL, 0);
    nostr_nip05_free_relays(NULL, 5);
}

static void test_nip05_parse_response_invalid_relay_url(void) {
    const char* json = "{"
        "\"names\":{\"bob\":\"" TEST_PUBKEY "\"},"
        "\"relays\":{\"" TEST_PUBKEY "\":[\"https://not-a-relay.com\",\"wss://valid.relay.com\",\"ftp://bad.com\"]}"
        "}";
    char pubkey[65];
    char** relays = NULL;
    size_t relay_count = 0;

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_parse_response(json, "bob", pubkey, sizeof(pubkey), &relays, &relay_count));
    TEST_ASSERT_EQUAL(1, relay_count);
    TEST_ASSERT_NOT_NULL(relays);
    TEST_ASSERT_EQUAL_STRING("wss://valid.relay.com", relays[0]);

    nostr_nip05_free_relays(relays, relay_count);
}

static void test_nip05_parse_response_json_injection(void) {
    const char* json = "{\"comment\":\"fake \\\"names\\\":{\\\"bob\\\":\\\"0000000000000000000000000000000000000000000000000000000000000000\\\"}\",\"names\":{\"bob\":\"" TEST_PUBKEY "\"}}";
    char pubkey[65];

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_parse_response(json, "bob", pubkey, sizeof(pubkey), NULL, NULL));
    TEST_ASSERT_EQUAL_STRING(TEST_PUBKEY, pubkey);
}

static void test_nip05_parse_response_ws_relay(void) {
    const char* json = "{"
        "\"names\":{\"bob\":\"" TEST_PUBKEY "\"},"
        "\"relays\":{\"" TEST_PUBKEY "\":[\"ws://insecure.relay.com\"]}"
        "}";
    char pubkey[65];
    char** relays = NULL;
    size_t relay_count = 0;

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip05_parse_response(json, "bob", pubkey, sizeof(pubkey), &relays, &relay_count));
    TEST_ASSERT_EQUAL(1, relay_count);
    TEST_ASSERT_EQUAL_STRING("ws://insecure.relay.com", relays[0]);

    nostr_nip05_free_relays(relays, relay_count);
}

void run_nip05_tests(void) {
    printf("   Running NIP-05 DNS identity verification tests...\n");

    UNITY_BEGIN();

    RUN_TEST(test_nip05_parse_basic);
    RUN_TEST(test_nip05_parse_root_identifier);
    RUN_TEST(test_nip05_parse_subdomain);
    RUN_TEST(test_nip05_parse_with_numbers);
    RUN_TEST(test_nip05_parse_case_insensitive);
    RUN_TEST(test_nip05_parse_invalid_no_at);
    RUN_TEST(test_nip05_parse_invalid_no_domain);
    RUN_TEST(test_nip05_parse_invalid_no_name);
    RUN_TEST(test_nip05_parse_invalid_domain_no_dot);
    RUN_TEST(test_nip05_parse_null_params);
    RUN_TEST(test_nip05_build_url_basic);
    RUN_TEST(test_nip05_build_url_root);
    RUN_TEST(test_nip05_build_url_subdomain);
    RUN_TEST(test_nip05_build_url_null_params);
    RUN_TEST(test_nip05_build_url_buffer_too_small);
    RUN_TEST(test_nip05_parse_response_basic);
    RUN_TEST(test_nip05_parse_response_with_relays);
    RUN_TEST(test_nip05_parse_response_name_not_found);
    RUN_TEST(test_nip05_parse_response_invalid_pubkey_length);
    RUN_TEST(test_nip05_parse_response_no_names);
    RUN_TEST(test_nip05_parse_response_null_params);
    RUN_TEST(test_nip05_verify_success);
    RUN_TEST(test_nip05_verify_with_relays);
    RUN_TEST(test_nip05_verify_wrong_pubkey);
    RUN_TEST(test_nip05_verify_http_failure);
    RUN_TEST(test_nip05_verify_invalid_identifier);
    RUN_TEST(test_nip05_verify_null_params);
    RUN_TEST(test_nip05_free_relays_null);
    RUN_TEST(test_nip05_parse_response_invalid_relay_url);
    RUN_TEST(test_nip05_parse_response_json_injection);
    RUN_TEST(test_nip05_parse_response_ws_relay);

    UNITY_END();

    printf("   NIP-05 tests completed\n");
}

#ifndef TEST_RUNNER_INCLUDED
int main(void) {
    run_nip05_tests();
    return 0;
}
#endif
