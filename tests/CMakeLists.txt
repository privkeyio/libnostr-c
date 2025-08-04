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

if(NOSTR_FEATURE_HD_KEYS)
    add_executable(test_hd_key test_hd_key.c)
    add_executable(test_hd_integration test_hd_integration.c)
    target_link_libraries(test_hd_key nostr_static)
    target_link_libraries(test_hd_integration nostr_static)
    add_test(NAME hd_key_tests COMMAND test_hd_key)
    add_test(NAME hd_integration_tests COMMAND test_hd_integration)
endif()

target_link_libraries(test_runner nostr_static)
if(UNITY_FOUND)
    target_link_libraries(test_runner ${UNITY_LIBRARIES})
    target_include_directories(test_runner PRIVATE ${UNITY_INCLUDE_DIRS})
    target_compile_options(test_runner PRIVATE ${UNITY_CFLAGS_OTHER})
endif()

add_test(NAME unit_tests COMMAND test_runner)