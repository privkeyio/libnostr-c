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
    test_relay.c
    test_zap.c
    test_utils.c
    test_runner.c
)

# Conditionally build tests based on enabled features
if(NOSTR_FEATURE_NIP59)
    add_executable(test_nip59 test_nip59.c)
    target_link_libraries(test_nip59 nostr_static)
    add_test(NAME nip59_tests COMMAND test_nip59)
endif()

if(NOSTR_FEATURE_NIP47)
    add_executable(test_nip47 test_nip47_minimal.c)
    target_link_libraries(test_nip47 nostr_static)
    add_test(NAME nip47_tests COMMAND test_nip47)
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
    target_link_libraries(test_hd_key nostr_static)
    target_link_libraries(test_hd_integration nostr_static)
    add_test(NAME hd_key_tests COMMAND test_hd_key)
    add_test(NAME hd_integration_tests COMMAND test_hd_integration)
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
endif()

target_link_libraries(test_runner nostr_static)
if(UNITY_FOUND)
    target_link_libraries(test_runner ${UNITY_LIBRARIES})
    target_include_directories(test_runner PRIVATE ${UNITY_INCLUDE_DIRS})
    target_compile_options(test_runner PRIVATE ${UNITY_CFLAGS_OTHER})
endif()

add_test(NAME unit_tests COMMAND test_runner)