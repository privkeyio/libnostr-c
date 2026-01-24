find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(UNITY unity)
endif()

if(NOT UNITY_FOUND)
    message(WARNING "Unity test framework not found, creating minimal test runner")
endif()

add_executable(test_runner
    test_event.c
    test_key.c
    test_bech32.c
    test_nip05.c
    test_nip21.c
    test_relay.c
    test_zap.c
    test_nip10.c
    test_nip18.c
    test_nip25.c
    test_utils.c
    test_runner.c
)

# Conditionally build tests based on enabled features
if(NOSTR_FEATURE_NIP05)
    add_executable(test_nip05 test_nip05.c)
    target_link_libraries(test_nip05 nostr_static)
    add_test(NAME nip05_tests COMMAND test_nip05)
endif()

if(NOSTR_FEATURE_NIP10)
    add_executable(test_nip10 test_nip10.c)
    target_link_libraries(test_nip10 nostr_static)
    add_test(NAME nip10_tests COMMAND test_nip10)
endif()

if(NOSTR_FEATURE_NIP18)
    add_executable(test_nip18 test_nip18.c)
    target_link_libraries(test_nip18 nostr_static)
    add_test(NAME nip18_tests COMMAND test_nip18)
endif()

if(NOSTR_FEATURE_NIP25)
    add_executable(test_nip25 test_nip25.c)
    target_link_libraries(test_nip25 nostr_static)
    add_test(NAME nip25_tests COMMAND test_nip25)
endif()

if(NOSTR_FEATURE_NIP26 AND HAVE_CRYPTO_BACKEND)
    add_executable(test_nip26 test_nip26.c)
    target_link_libraries(test_nip26 nostr_static)
    add_test(NAME nip26_tests COMMAND test_nip26)
endif()

if(NOSTR_FEATURE_NIP59)
    add_executable(test_nip59 test_nip59.c)
    target_link_libraries(test_nip59 nostr_static)
    add_test(NAME nip59_tests COMMAND test_nip59)
endif()

if(NOSTR_FEATURE_NIP65)
    add_executable(test_nip65 test_nip65.c)
    target_link_libraries(test_nip65 nostr_static)
    add_test(NAME nip65_tests COMMAND test_nip65)
endif()

if(NOSTR_FEATURE_NIP47)
    add_executable(test_nip47 test_nip47_minimal.c)
    target_link_libraries(test_nip47 nostr_static)
    add_test(NAME nip47_tests COMMAND test_nip47)
endif()

if(NOSTR_FEATURE_NIP49)
    add_executable(test_nip49 test_nip49.c)
    target_link_libraries(test_nip49 nostr_static)
    add_test(NAME nip49_tests COMMAND test_nip49)
endif()

if(NOSTR_FEATURE_NIP04)
    add_executable(test_nip04 test_nip04.c)
    target_link_libraries(test_nip04 nostr_static)
    add_test(NAME nip04_tests COMMAND test_nip04)
endif()

if(NOSTR_FEATURE_NIP44)
    add_executable(test_nip44 test_nip44.c)
    target_link_libraries(test_nip44 nostr_static)
    add_test(NAME nip44_tests COMMAND test_nip44)

    add_executable(test_nip44_comprehensive test_nip44_comprehensive.c)
    target_link_libraries(test_nip44_comprehensive nostr_static)
    add_test(NAME nip44_comprehensive_tests COMMAND test_nip44_comprehensive)
endif()

if(NOSTR_FEATURE_HD_KEYS)
    add_executable(test_hd_key test_hd_key.c)
    add_executable(test_hd_integration test_hd_integration.c)
    add_executable(test_nip06 test_nip06.c)
    target_link_libraries(test_hd_key nostr_static)
    target_link_libraries(test_hd_integration nostr_static)
    target_link_libraries(test_nip06 nostr_static)
    add_test(NAME hd_key_tests COMMAND test_hd_key)
    add_test(NAME hd_integration_tests COMMAND test_hd_integration)
    add_test(NAME nip06_tests COMMAND test_nip06)
endif()

if(NOSTR_FEATURE_RELAY_PROTOCOL)
    add_executable(test_relay_protocol
        test_relay_protocol.c
        test_relay_protocol_core.c
        test_relay_protocol_json.c
        test_relay_protocol_nip.c
        test_relay_protocol_accessors.c
    )
    target_compile_definitions(test_relay_protocol PRIVATE TEST_RUNNER_INCLUDED)
    target_link_libraries(test_relay_protocol nostr_static)
    add_test(NAME relay_protocol_tests COMMAND test_relay_protocol)

    add_executable(test_relay_integration test_relay_integration.c)
    target_link_libraries(test_relay_integration nostr_static)
    add_test(NAME relay_integration_tests COMMAND test_relay_integration)

    add_executable(test_filter_clone test_filter_clone.c)
    target_link_libraries(test_filter_clone nostr_static)
    add_test(NAME filter_clone_tests COMMAND test_filter_clone)
endif()

target_link_libraries(test_runner nostr_static)
target_compile_definitions(test_runner PRIVATE TEST_RUNNER_INCLUDED)
if(UNITY_FOUND)
    target_link_libraries(test_runner ${UNITY_LIBRARIES})
    target_include_directories(test_runner PRIVATE ${UNITY_INCLUDE_DIRS})
    target_compile_options(test_runner PRIVATE ${UNITY_CFLAGS_OTHER})
endif()

add_test(NAME unit_tests COMMAND test_runner)