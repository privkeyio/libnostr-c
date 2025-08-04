#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "../include/nostr.h"

void print_hex(const char* label, const uint8_t* data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void test_nip59_rumor_creation()
{
    printf("Testing NIP-59 rumor creation...\n");
    
    nostr_error_t err = nostr_init();
    assert(err == NOSTR_OK);
    
    nostr_key pubkey;
    nostr_privkey privkey;
    err = nostr_key_generate(&privkey, &pubkey);
    assert(err == NOSTR_OK);
    
    nostr_event* rumor = NULL;
    err = nostr_nip59_create_rumor(&rumor, 1, &pubkey, "Test rumor content");
    assert(err == NOSTR_OK);
    assert(rumor != NULL);
    assert(rumor->kind == 1);
    assert(memcmp(&rumor->pubkey, &pubkey, sizeof(nostr_key)) == 0);
    assert(strcmp(rumor->content, "Test rumor content") == 0);
    
    /* Verify signature is empty (rumor is unsigned) */
    uint8_t empty_sig[NOSTR_SIG_SIZE] = {0};
    assert(memcmp(rumor->sig, empty_sig, NOSTR_SIG_SIZE) == 0);
    
    nostr_event_destroy(rumor);
    printf("Success: Rumor creation successful\n");
}

void test_nip59_seal_creation()
{
    printf("Testing NIP-59 seal creation...\n");
    
    nostr_privkey author_privkey;
    nostr_key author_pubkey;
    nostr_error_t err = nostr_key_generate(&author_privkey, &author_pubkey);
    assert(err == NOSTR_OK);
    
    nostr_privkey recipient_privkey;
    nostr_key recipient_pubkey;
    err = nostr_key_generate(&recipient_privkey, &recipient_pubkey);
    assert(err == NOSTR_OK);
    
    /* Create rumor */
    nostr_event* rumor = NULL;
    err = nostr_nip59_create_rumor(&rumor, 1, &author_pubkey, "Secret message");
    assert(err == NOSTR_OK);
    
    /* Create seal */
    nostr_event* seal = NULL;
    err = nostr_nip59_create_seal(&seal, rumor, &author_privkey, &recipient_pubkey);
    assert(err == NOSTR_OK);
    assert(seal != NULL);
    assert(seal->kind == 13);
    assert(seal->content != NULL && strlen(seal->content) > 0);
    
    /* Verify signature */
    err = nostr_event_verify(seal);
    assert(err == NOSTR_OK);
    
    /* Verify author pubkey matches */
    assert(memcmp(&seal->pubkey, &author_pubkey, sizeof(nostr_key)) == 0);
    
    nostr_event_destroy(rumor);
    nostr_event_destroy(seal);
    printf("Success: Seal creation successful\n");
}

void test_nip59_gift_wrap_complete_flow()
{
    printf("Testing NIP-59 complete gift wrap flow...\n");
    
    nostr_privkey author_privkey;
    nostr_key author_pubkey;
    nostr_error_t err = nostr_key_generate(&author_privkey, &author_pubkey);
    assert(err == NOSTR_OK);
    
    nostr_privkey recipient_privkey;
    nostr_key recipient_pubkey;
    err = nostr_key_generate(&recipient_privkey, &recipient_pubkey);
    assert(err == NOSTR_OK);
    
    /* Create original event */
    nostr_event* original = NULL;
    err = nostr_event_create(&original);
    assert(err == NOSTR_OK);
    
    original->kind = 1;
    original->created_at = time(NULL);
    memcpy(&original->pubkey, &author_pubkey, sizeof(nostr_key));
    err = nostr_event_set_content(original, "This is a test note");
    assert(err == NOSTR_OK);
    
    const char* tag_values[2] = {"subject", "Test Subject"};
    err = nostr_event_add_tag(original, tag_values, 2);
    assert(err == NOSTR_OK);
    
    err = nostr_event_compute_id(original);
    assert(err == NOSTR_OK);
    err = nostr_event_sign(original, &author_privkey);
    assert(err == NOSTR_OK);
    
    /* Wrap the event */
    nostr_event* gift_wrap = NULL;
    err = nostr_nip59_wrap_event(&gift_wrap, original, &author_privkey, &recipient_pubkey);
    assert(err == NOSTR_OK);
    assert(gift_wrap != NULL);
    assert(gift_wrap->kind == 1059);
    
    /* Verify gift wrap has p tag */
    int has_p_tag = 0;
    for (size_t i = 0; i < gift_wrap->tags_count; i++) {
        if (strcmp(gift_wrap->tags[i].values[0], "p") == 0) {
            has_p_tag = 1;
            break;
        }
    }
    assert(has_p_tag);
    
    /* Unwrap the event */
    nostr_event* unwrapped = NULL;
    nostr_key unwrapped_author;
    err = nostr_nip59_unwrap_event(gift_wrap, &recipient_privkey, &unwrapped, &unwrapped_author);
    assert(err == NOSTR_OK);
    assert(unwrapped != NULL);
    
    /* Verify unwrapped event matches original */
    assert(unwrapped->kind == original->kind);
    assert(strcmp(unwrapped->content, original->content) == 0);
    assert(memcmp(&unwrapped_author, &author_pubkey, sizeof(nostr_key)) == 0);
    
    nostr_event_destroy(original);
    nostr_event_destroy(gift_wrap);
    nostr_event_destroy(unwrapped);
    printf("Success: Complete gift wrap flow successful\n");
}

void test_nip59_metadata_protection()
{
    printf("Testing NIP-59 metadata protection...\n");
    
    nostr_privkey author_privkey;
    nostr_key author_pubkey;
    nostr_error_t err = nostr_key_generate(&author_privkey, &author_pubkey);
    assert(err == NOSTR_OK);
    
    nostr_privkey recipient_privkey;
    nostr_key recipient_pubkey;
    err = nostr_key_generate(&recipient_privkey, &recipient_pubkey);
    assert(err == NOSTR_OK);
    
    /* Create event with sensitive metadata */
    nostr_event* sensitive = NULL;
    err = nostr_event_create(&sensitive);
    assert(err == NOSTR_OK);
    
    sensitive->kind = 14;  /* DM kind */
    sensitive->created_at = 1234567890;  /* Specific timestamp */
    memcpy(&sensitive->pubkey, &author_pubkey, sizeof(nostr_key));
    err = nostr_event_set_content(sensitive, "Secret DM content");
    assert(err == NOSTR_OK);
    
    /* Add various tags */
    const char* p_tag[2] = {"p", "deadbeef"};
    const char* e_tag[2] = {"e", "cafebabe"};
    const char* subject_tag[2] = {"subject", "Secret Subject"};
    
    err = nostr_event_add_tag(sensitive, p_tag, 2);
    assert(err == NOSTR_OK);
    err = nostr_event_add_tag(sensitive, e_tag, 2);
    assert(err == NOSTR_OK);
    err = nostr_event_add_tag(sensitive, subject_tag, 2);
    assert(err == NOSTR_OK);
    
    err = nostr_event_compute_id(sensitive);
    assert(err == NOSTR_OK);
    err = nostr_event_sign(sensitive, &author_privkey);
    assert(err == NOSTR_OK);
    
    /* Wrap the event */
    nostr_event* gift_wrap = NULL;
    err = nostr_nip59_wrap_event(&gift_wrap, sensitive, &author_privkey, &recipient_pubkey);
    assert(err == NOSTR_OK);
    
    /* Verify metadata is hidden */
    assert(gift_wrap->kind == 1059);
    assert(gift_wrap->created_at != sensitive->created_at);  /* Timestamp randomized */
    assert(memcmp(&gift_wrap->pubkey, &author_pubkey, sizeof(nostr_key)) != 0);  /* Ephemeral key */
    
    /* Verify only p tag is visible */
    assert(gift_wrap->tags_count == 1);
    assert(strcmp(gift_wrap->tags[0].values[0], "p") == 0);
    
    /* Verify content is encrypted */
    assert(strstr(gift_wrap->content, "Secret") == NULL);
    
    nostr_event_destroy(sensitive);
    nostr_event_destroy(gift_wrap);
    printf("Success: Metadata protection successful\n");
}

void test_nip59_integration_with_nip17()
{
    printf("Testing NIP-59 integration with NIP-17...\n");
    
    nostr_privkey sender_privkey;
    nostr_key sender_pubkey;
    nostr_error_t err = nostr_key_generate(&sender_privkey, &sender_pubkey);
    assert(err == NOSTR_OK);
    
    nostr_privkey recipient_privkey;
    nostr_key recipient_pubkey;
    err = nostr_key_generate(&recipient_privkey, &recipient_pubkey);
    assert(err == NOSTR_OK);
    
    /* Send DM using NIP-17 (which uses NIP-59 internally) */
    nostr_event* dm = NULL;
    err = nostr_nip17_send_dm(&dm, "Hello, this is a test DM", 
                              &sender_privkey, &recipient_pubkey, 
                              "Test Subject", NULL, 0);
    assert(err == NOSTR_OK);
    assert(dm != NULL);
    assert(dm->kind == 1059);  /* Gift wrap */
    
    /* Unwrap using NIP-17 */
    nostr_event* rumor = NULL;
    nostr_key unwrapped_sender;
    err = nostr_nip17_unwrap_dm(dm, &recipient_privkey, &rumor, &unwrapped_sender);
    assert(err == NOSTR_OK);
    assert(rumor != NULL);
    assert(rumor->kind == 14);  /* DM kind */
    assert(strcmp(rumor->content, "Hello, this is a test DM") == 0);
    assert(memcmp(&unwrapped_sender, &sender_pubkey, sizeof(nostr_key)) == 0);
    
    /* Also test unwrapping with NIP-59 directly */
    nostr_event* unwrapped_event = NULL;
    nostr_key seal_author;
    err = nostr_nip59_unwrap_event(dm, &recipient_privkey, &unwrapped_event, &seal_author);
    assert(err == NOSTR_OK);
    assert(unwrapped_event != NULL);
    assert(unwrapped_event->kind == 14);
    assert(strcmp(unwrapped_event->content, "Hello, this is a test DM") == 0);
    
    nostr_event_destroy(dm);
    nostr_event_destroy(rumor);
    nostr_event_destroy(unwrapped_event);
    printf("Success: NIP-17 integration successful\n");
}

void test_nip59_error_cases()
{
    printf("Testing NIP-59 error cases...\n");
    
    nostr_privkey privkey;
    nostr_key pubkey;
    nostr_error_t err = nostr_key_generate(&privkey, &pubkey);
    assert(err == NOSTR_OK);
    
    /* Test NULL parameters */
    err = nostr_nip59_create_rumor(NULL, 1, &pubkey, "content");
    assert(err == NOSTR_ERR_INVALID_PARAM);
    
    nostr_event* rumor = NULL;
    err = nostr_nip59_create_rumor(&rumor, 1, NULL, "content");
    assert(err == NOSTR_ERR_INVALID_PARAM);
    
    /* Test unwrapping wrong kind */
    nostr_event* wrong_kind = NULL;
    err = nostr_event_create(&wrong_kind);
    assert(err == NOSTR_OK);
    wrong_kind->kind = 1;  /* Not a gift wrap */
    
    nostr_event* unwrapped = NULL;
    err = nostr_nip59_unwrap_event(wrong_kind, &privkey, &unwrapped, NULL);
    assert(err == NOSTR_ERR_INVALID_EVENT);
    
    nostr_event_destroy(wrong_kind);
    printf("Success: Error handling successful\n");
}

int main()
{
    printf("=== NIP-59 Gift Wrap Tests ===\n\n");
    
    test_nip59_rumor_creation();
    test_nip59_seal_creation();
    test_nip59_gift_wrap_complete_flow();
    test_nip59_metadata_protection();
    test_nip59_integration_with_nip17();
    test_nip59_error_cases();
    
    printf("\nSuccess: All NIP-59 tests passed!\n");
    return 0;
}