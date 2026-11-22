#include "unity.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/nostr.h"

void test_event_create_destroy(void)
{
    nostr_event* event = NULL;
    
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_TRUE(event->created_at > 0);
    TEST_ASSERT_EQUAL(0, event->tags_count);
    TEST_ASSERT_NULL(event->content);
    TEST_ASSERT_NULL(event->tags);
    
    nostr_event_destroy(event);
}

void test_event_create_invalid_param(void)
{
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_create(NULL));
}

void test_event_set_content(void)
{
    nostr_event* event = NULL;
    nostr_event_create(&event);
    
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_set_content(event, "Hello Nostr!"));
    TEST_ASSERT_NOT_NULL(event->content);
    TEST_ASSERT_EQUAL_STRING("Hello Nostr!", event->content);
    
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_set_content(event, "Updated content"));
    TEST_ASSERT_EQUAL_STRING("Updated content", event->content);
    
    nostr_event_destroy(event);
}

void test_event_set_content_invalid_params(void)
{
    nostr_event* event = NULL;
    nostr_event_create(&event);
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_set_content(NULL, "content"));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_set_content(event, NULL));
    
    nostr_event_destroy(event);
}

void test_event_add_tag(void)
{
    nostr_event* event = NULL;
    nostr_event_create(&event);
    
    const char* tag_values[] = {"e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36"};
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_add_tag(event, tag_values, 2));
    
    TEST_ASSERT_EQUAL(1, event->tags_count);
    TEST_ASSERT_EQUAL(2, event->tags[0].count);
    TEST_ASSERT_EQUAL_STRING("e", event->tags[0].values[0]);
    TEST_ASSERT_EQUAL_STRING("5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", event->tags[0].values[1]);
    
    const char* p_tag[] = {"p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca"};
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_add_tag(event, p_tag, 2));
    
    TEST_ASSERT_EQUAL(2, event->tags_count);
    TEST_ASSERT_EQUAL_STRING("p", event->tags[1].values[0]);
    
    nostr_event_destroy(event);
}

static void require_aligned_values(const nostr_event* event)
{
    for (size_t i = 0; i < event->tags_count; i++) {
        if ((uintptr_t)event->tags[i].values % sizeof(char*) != 0) {
            char msg[64];
            snprintf(msg, sizeof(msg), "tag %zu values array is misaligned", i);
            TEST_FAIL_MESSAGE(msg);
        }
    }
}

void test_event_tag_values_aligned(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));

    char value[80];
    for (size_t n = 1; n < sizeof(value); n++) {
        memset(value, 'x', n);
        value[n] = '\0';
        const char* tag[] = {"t", value};
        TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_add_tag(event, tag, 2));
    }
    require_aligned_values(event);
    TEST_ASSERT_EQUAL_STRING("xxx", event->tags[2].values[1]);

#ifdef NOSTR_FEATURE_NIP13
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip13_add_nonce_tag(event, 1, 0));
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_nip13_add_nonce_tag(event, 123, 8));
    require_aligned_values(event);
    TEST_ASSERT_EQUAL_STRING("8", event->tags[event->tags_count - 1].values[2]);
#endif

    nostr_event_destroy(event);
}

void test_event_add_tag_invalid_params(void)
{
    nostr_event* event = NULL;
    nostr_event_create(&event);
    
    const char* tag_values[] = {"e", "test"};
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_add_tag(NULL, tag_values, 2));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_add_tag(event, NULL, 2));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_add_tag(event, tag_values, 0));
    
    nostr_event_destroy(event);
}

void test_event_compute_id(void)
{
    nostr_event* event = NULL;
    nostr_event_create(&event);
    
    event->kind = 1;
    nostr_event_set_content(event, "Hello Nostr!");
    
    uint8_t test_pubkey[32] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 
                               0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                               0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 
                               0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    memcpy(event->pubkey.data, test_pubkey, 32);
    
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_compute_id(event));
    
    uint8_t zero_id[32] = {0};
    TEST_ASSERT_NOT_EQUAL(0, memcmp(event->id, zero_id, 32));
    
    nostr_event_destroy(event);
}

void test_event_compute_id_many_tags(void)
{
    nostr_event* event = NULL;
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_create(&event));
    event->kind = 1;
    event->created_at = 1234567890;
    nostr_event_set_content(event, "x");
    for (int i = 0; i < 32; i += 8) {
        const uint8_t chunk[8] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
        memcpy(event->pubkey.data + i, chunk, 8);
    }

    const char* empty[1] = {""};
    for (int i = 0; i < 600; i++) {
        TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_add_tag(event, empty, 1));
    }
    const char* escaped[2] = {"e", "a\"b\\\n"};
    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_add_tag(event, escaped, 2));

    TEST_ASSERT_EQUAL(NOSTR_OK, nostr_event_compute_id(event));

    const uint8_t expected[32] = {
        0x4a, 0x56, 0x0c, 0xd0, 0xb3, 0xf6, 0xe5, 0x68, 0xe1, 0x46, 0x47, 0xc0, 0x8a, 0x86, 0xf4, 0xf8,
        0xcf, 0x9e, 0x21, 0x53, 0x4a, 0x75, 0x4f, 0x96, 0x41, 0x75, 0x9d, 0xd1, 0x79, 0x10, 0x0f, 0x89};
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected, event->id, 32, "event ID mismatch for many-tags event");

    nostr_event_destroy(event);
}

void test_event_to_json(void)
{
    nostr_event* event = NULL;
    nostr_event_create(&event);
    
    event->kind = 1;
    event->created_at = 1234567890;
    nostr_event_set_content(event, "Hello Nostr!");
    
    uint8_t test_pubkey[32] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 
                               0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                               0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 
                               0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    memcpy(event->pubkey.data, test_pubkey, 32);
    
    const char* tag_values[] = {"e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36"};
    nostr_event_add_tag(event, tag_values, 2);
    
    nostr_event_compute_id(event);
    
    char* json = NULL;
    nostr_error_t result = nostr_event_to_json(event, &json);
    
    #ifdef HAVE_CJSON
    TEST_ASSERT_EQUAL(NOSTR_OK, result);
    TEST_ASSERT_NOT_NULL(json);
    TEST_ASSERT_TRUE(strstr(json, "\"kind\"") != NULL);
    free(json);
    #else
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, result);
    #endif
    
    nostr_event_destroy(event);
}

void test_event_from_json(void)
{
    const char* json = "{"
        "\"id\":\"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\","
        "\"pubkey\":\"123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0\","
        "\"created_at\":1234567890,"
        "\"kind\":1,"
        "\"tags\":[[\"e\",\"5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36\"]],"
        "\"content\":\"Hello Nostr!\","
        "\"sig\":\"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\""
    "}";
    
    nostr_event* event = NULL;
    nostr_error_t result = nostr_event_from_json(json, &event);
    
    #ifdef HAVE_CJSON
    TEST_ASSERT_EQUAL(NOSTR_OK, result);
    TEST_ASSERT_NOT_NULL(event);
    TEST_ASSERT_EQUAL(1, event->kind);
    TEST_ASSERT_EQUAL(1234567890, event->created_at);
    TEST_ASSERT_EQUAL_STRING("Hello Nostr!", event->content);
    TEST_ASSERT_EQUAL(1, event->tags_count);
    TEST_ASSERT_EQUAL_STRING("e", event->tags[0].values[0]);
    nostr_event_destroy(event);
    #else
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, result);
    #endif
}

void test_event_from_json_invalid(void)
{
    nostr_event* event = NULL;
    
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_from_json(NULL, &event));
    TEST_ASSERT_EQUAL(NOSTR_ERR_INVALID_PARAM, nostr_event_from_json("{}", NULL));
    
    #ifdef HAVE_CJSON
    TEST_ASSERT_EQUAL(NOSTR_ERR_JSON_PARSE, nostr_event_from_json("invalid json", &event));
    #else
    TEST_ASSERT_EQUAL(NOSTR_ERR_ENCODING, nostr_event_from_json("invalid json", &event));
    #endif
}

void run_event_tests(void)
{
    RUN_TEST(test_event_create_destroy);
    RUN_TEST(test_event_create_invalid_param);
    RUN_TEST(test_event_set_content);
    RUN_TEST(test_event_set_content_invalid_params);
    RUN_TEST(test_event_add_tag);
    RUN_TEST(test_event_add_tag_invalid_params);
    RUN_TEST(test_event_tag_values_aligned);
    RUN_TEST(test_event_compute_id);
    RUN_TEST(test_event_compute_id_many_tags);
    RUN_TEST(test_event_to_json);
    RUN_TEST(test_event_from_json);
    RUN_TEST(test_event_from_json_invalid);
}