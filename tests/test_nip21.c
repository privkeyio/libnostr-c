#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../include/nostr.h"
#include "unity.h"

static void test_uri_parse_npub(void) {
    nostr_uri uri;
    const char* test_uri = "nostr:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_uri_parse(test_uri, &uri));
    TEST_ASSERT_EQUAL(NOSTR_URI_NPUB, uri.type);

    char hex[65];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_to_hex(&uri.data.npub, hex, sizeof(hex)));
    TEST_ASSERT_EQUAL_STRING("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", hex);

    nostr_uri_free(&uri);
}

static void test_uri_parse_nsec(void) {
    nostr_uri uri;
    const char* test_uri = "nostr:nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_uri_parse(test_uri, &uri));
    TEST_ASSERT_EQUAL(NOSTR_URI_NSEC, uri.type);

    char hex[65];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_privkey_to_hex(&uri.data.nsec, hex, sizeof(hex)));
    TEST_ASSERT_EQUAL_STRING("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa", hex);

    nostr_uri_free(&uri);
}

static void test_uri_parse_note(void) {
    nostr_uri uri;
    const char* test_uri = "nostr:note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc";

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_uri_parse(test_uri, &uri));
    TEST_ASSERT_EQUAL(NOSTR_URI_NOTE, uri.type);

    nostr_uri_free(&uri);
}

static void test_uri_encode_npub(void) {
    nostr_uri uri;
    memset(&uri, 0, sizeof(uri));
    uri.type = NOSTR_URI_NPUB;

    const char* hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_from_hex(hex, &uri.data.npub));

    char output[256];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_uri_encode(&uri, output, sizeof(output)));
    TEST_ASSERT_EQUAL_STRING("nostr:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6", output);
}

static void test_uri_roundtrip(void) {
    const char* original = "nostr:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";

    nostr_uri uri;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_uri_parse(original, &uri));

    char output[256];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_uri_encode(&uri, output, sizeof(output)));
    TEST_ASSERT_EQUAL_STRING(original, output);

    nostr_uri_free(&uri);
}

static void test_nprofile_basic(void) {
    nostr_nprofile profile;
    memset(&profile, 0, sizeof(profile));

    const char* pubkey_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_from_hex(pubkey_hex, &profile.pubkey));

    char bech32[512];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nprofile_encode(&profile, bech32, sizeof(bech32)));
    TEST_ASSERT_TRUE(strncmp(bech32, "nprofile1", 9) == 0);

    nostr_nprofile decoded;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nprofile_decode(bech32, &decoded));

    char decoded_hex[65];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_to_hex(&decoded.pubkey, decoded_hex, sizeof(decoded_hex)));
    TEST_ASSERT_EQUAL_STRING(pubkey_hex, decoded_hex);

    nostr_nprofile_free(&decoded);
}

static void test_nprofile_with_relays(void) {
    nostr_nprofile profile;
    memset(&profile, 0, sizeof(profile));

    const char* pubkey_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_from_hex(pubkey_hex, &profile.pubkey));

    profile.relays[0] = strdup("wss://relay.example.com");
    profile.relays[1] = strdup("wss://relay2.example.com");
    profile.relay_count = 2;

    char bech32[1024];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nprofile_encode(&profile, bech32, sizeof(bech32)));

    nostr_nprofile decoded;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nprofile_decode(bech32, &decoded));

    TEST_ASSERT_EQUAL(2, decoded.relay_count);
    TEST_ASSERT_EQUAL_STRING("wss://relay.example.com", decoded.relays[0]);
    TEST_ASSERT_EQUAL_STRING("wss://relay2.example.com", decoded.relays[1]);

    nostr_nprofile_free(&profile);
    nostr_nprofile_free(&decoded);
}

static void test_nevent_basic(void) {
    nostr_nevent nevent;
    memset(&nevent, 0, sizeof(nevent));

    const char* id_hex = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
    TEST_ASSERT_EQUAL(32, nostr_hex_decode(id_hex, nevent.id, 32));

    char bech32[512];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nevent_encode(&nevent, bech32, sizeof(bech32)));
    TEST_ASSERT_TRUE(strncmp(bech32, "nevent1", 7) == 0);

    nostr_nevent decoded;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nevent_decode(bech32, &decoded));
    TEST_ASSERT_EQUAL_MEMORY(nevent.id, decoded.id, 32);

    nostr_nevent_free(&decoded);
}

static void test_nevent_with_metadata(void) {
    nostr_nevent nevent;
    memset(&nevent, 0, sizeof(nevent));

    const char* id_hex = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
    TEST_ASSERT_EQUAL(32, nostr_hex_decode(id_hex, nevent.id, 32));

    const char* author_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_from_hex(author_hex, &nevent.author));
    nevent.has_author = 1;

    nevent.kind = 1;
    nevent.has_kind = 1;

    nevent.relays[0] = strdup("wss://relay.example.com");
    nevent.relay_count = 1;

    char bech32[1024];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nevent_encode(&nevent, bech32, sizeof(bech32)));

    nostr_nevent decoded;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nevent_decode(bech32, &decoded));

    TEST_ASSERT_EQUAL(1, decoded.has_author);
    TEST_ASSERT_EQUAL(1, decoded.has_kind);
    TEST_ASSERT_EQUAL(1, decoded.kind);
    TEST_ASSERT_EQUAL(1, decoded.relay_count);

    nostr_nevent_free(&nevent);
    nostr_nevent_free(&decoded);
}

static void test_naddr_basic(void) {
    nostr_naddr addr;
    memset(&addr, 0, sizeof(addr));

    strcpy(addr.identifier, "test-article");

    const char* pubkey_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_from_hex(pubkey_hex, &addr.pubkey));

    addr.kind = 30023;

    char bech32[1024];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_naddr_encode(&addr, bech32, sizeof(bech32)));
    TEST_ASSERT_TRUE(strncmp(bech32, "naddr1", 6) == 0);

    nostr_naddr decoded;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_naddr_decode(bech32, &decoded));

    TEST_ASSERT_EQUAL_STRING("test-article", decoded.identifier);
    TEST_ASSERT_EQUAL(30023, decoded.kind);

    nostr_naddr_free(&decoded);
}

static void test_nrelay_basic(void) {
    nostr_nrelay relay;
    memset(&relay, 0, sizeof(relay));
    strcpy(relay.url, "wss://relay.example.com");

    char bech32[512];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nrelay_encode(&relay, bech32, sizeof(bech32)));
    TEST_ASSERT_TRUE(strncmp(bech32, "nrelay1", 7) == 0);

    nostr_nrelay decoded;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nrelay_decode(bech32, &decoded));
    TEST_ASSERT_EQUAL_STRING("wss://relay.example.com", decoded.url);
}

static void test_uri_parse_nprofile(void) {
    nostr_nprofile profile;
    memset(&profile, 0, sizeof(profile));

    const char* pubkey_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_key_from_hex(pubkey_hex, &profile.pubkey));
    profile.relays[0] = strdup("wss://relay.example.com");
    profile.relay_count = 1;

    char bech32[1024];
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nprofile_encode(&profile, bech32, sizeof(bech32)));

    char uri_str[1100];
    snprintf(uri_str, sizeof(uri_str), "nostr:%s", bech32);

    nostr_uri uri;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_uri_parse(uri_str, &uri));
    TEST_ASSERT_EQUAL(NOSTR_URI_NPROFILE, uri.type);
    TEST_ASSERT_EQUAL(1, uri.data.nprofile.relay_count);

    nostr_nprofile_free(&profile);
    nostr_uri_free(&uri);
}

static void test_uri_invalid_scheme(void) {
    nostr_uri uri;
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, nostr_uri_parse("http://example.com", &uri));
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, nostr_uri_parse("invalid", &uri));
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, nostr_uri_parse("nostr:invalid", &uri));
}

static void test_uri_null_params(void) {
    nostr_uri uri;
    char output[256];

    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_uri_parse(NULL, &uri));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_uri_parse("nostr:npub1...", NULL));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_uri_encode(NULL, output, sizeof(output)));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_uri_encode(&uri, NULL, sizeof(output)));
}

void run_nip21_tests(void) {
    printf("   Running NIP-21 URI scheme tests...\n");

    UNITY_BEGIN();

    RUN_TEST(test_uri_parse_npub);
    RUN_TEST(test_uri_parse_nsec);
    RUN_TEST(test_uri_parse_note);
    RUN_TEST(test_uri_encode_npub);
    RUN_TEST(test_uri_roundtrip);
    RUN_TEST(test_nprofile_basic);
    RUN_TEST(test_nprofile_with_relays);
    RUN_TEST(test_nevent_basic);
    RUN_TEST(test_nevent_with_metadata);
    RUN_TEST(test_naddr_basic);
    RUN_TEST(test_nrelay_basic);
    RUN_TEST(test_uri_parse_nprofile);
    RUN_TEST(test_uri_invalid_scheme);
    RUN_TEST(test_uri_null_params);

    UNITY_END();

    printf("   NIP-21 tests completed\n");
}
