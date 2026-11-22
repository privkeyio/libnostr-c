# Unity (MIT). An installed copy is used if found: first a CMake package (from
# Unity's own CMake install), then pkg-config (from its Meson install).
# Otherwise v2.6.0 is downloaded, pinned by commit like every other third-party
# source CI builds. Either way the tests link it through nostr_unity, and it is
# never installed with libnostr-c.
find_package(unity 2.6 CONFIG QUIET)
if(NOT TARGET unity::framework)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(NOSTR_UNITY_PC QUIET IMPORTED_TARGET unity>=2.6)
    endif()
endif()

if(TARGET unity::framework)
    message(STATUS "Unity: using the installed CMake package in ${unity_DIR}")
    add_library(nostr_unity INTERFACE)
    target_link_libraries(nostr_unity INTERFACE unity::framework)
elseif(NOSTR_UNITY_PC_FOUND)
    message(STATUS "Unity: using the installed pkg-config package ${NOSTR_UNITY_PC_VERSION}")
    add_library(nostr_unity INTERFACE)
    target_link_libraries(nostr_unity INTERFACE PkgConfig::NOSTR_UNITY_PC)
else()
    include(FetchContent)
    # Download only: Unity's own CMakeLists.txt adds install rules, which would
    # make `cmake --install` ship Unity alongside libnostr-c, so it never runs
    # and the single source is built here instead.
    if(CMAKE_VERSION VERSION_LESS 3.18)
        # SOURCE_SUBDIR needs 3.18, so populate without adding the project.
        FetchContent_Declare(unity
            GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
            GIT_TAG 860062d51b2e8a75d150337b63ca2a472840d13c # v2.6.0
        )
        FetchContent_GetProperties(unity)
        if(NOT unity_POPULATED)
            FetchContent_Populate(unity)
        endif()
    else()
        FetchContent_Declare(unity
            GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
            GIT_TAG 860062d51b2e8a75d150337b63ca2a472840d13c # v2.6.0
            SOURCE_SUBDIR no-cmake
        )
        FetchContent_MakeAvailable(unity)
    endif()
    message(STATUS "Unity: no installed copy found, downloaded v2.6.0")
    add_library(nostr_unity STATIC ${unity_SOURCE_DIR}/src/unity.c)
    target_include_directories(nostr_unity PUBLIC ${unity_SOURCE_DIR}/src)
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
    target_link_libraries(test_nip05 nostr_static nostr_unity)
    add_test(NAME nip05_tests COMMAND test_nip05)
endif()

if(NOSTR_FEATURE_NIP10)
    add_executable(test_nip10 test_nip10.c)
    target_link_libraries(test_nip10 nostr_static nostr_unity)
    add_test(NAME nip10_tests COMMAND test_nip10)
endif()

if(NOSTR_FEATURE_NIP18)
    add_executable(test_nip18 test_nip18.c)
    target_link_libraries(test_nip18 nostr_static nostr_unity)
    add_test(NAME nip18_tests COMMAND test_nip18)
endif()

if(NOSTR_FEATURE_NIP25)
    add_executable(test_nip25 test_nip25.c)
    target_link_libraries(test_nip25 nostr_static nostr_unity)
    add_test(NAME nip25_tests COMMAND test_nip25)
endif()

if(NOSTR_FEATURE_NIP26 AND HAVE_CRYPTO_BACKEND)
    add_executable(test_nip26 test_nip26.c)
    target_link_libraries(test_nip26 nostr_static nostr_unity)
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
    target_link_libraries(test_nip49 nostr_static nostr_unity)
    add_test(NAME nip49_tests COMMAND test_nip49)
endif()

if(NOSTR_FEATURE_NIP51)
    add_executable(test_nip51 test_nip51.c)
    target_link_libraries(test_nip51 nostr_static)
    add_test(NAME nip51_tests COMMAND test_nip51)
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
    target_link_libraries(test_relay_protocol nostr_static nostr_unity)
    add_test(NAME relay_protocol_tests COMMAND test_relay_protocol)

    add_executable(test_relay_integration test_relay_integration.c)
    target_link_libraries(test_relay_integration nostr_static)
    add_test(NAME relay_integration_tests COMMAND test_relay_integration)

    add_executable(test_filter_clone test_filter_clone.c)
    target_link_libraries(test_filter_clone nostr_static nostr_unity)
    add_test(NAME filter_clone_tests COMMAND test_filter_clone)

    add_executable(test_nip50 test_nip50.c)
    target_link_libraries(test_nip50 nostr_static nostr_unity)
    add_test(NAME nip50_tests COMMAND test_nip50)
endif()

# nostr_random_bytes() produces every private key, BIP-39 mnemonic, BIP-340
# aux_rand and NIP-44 nonce, and had no direct test on any platform. Threads are
# required for the concurrency case, which is the regression test for an
# unsynchronised DRBG draw.
find_package(Threads REQUIRED)
add_executable(test_random test_random.c)
target_link_libraries(test_random nostr_static nostr_unity Threads::Threads)
add_test(NAME random_tests COMMAND test_random)
# The deadlock case would hang rather than fail if that bug returned, and
# ctest's default timeout is 1500s. Cap it so a regression reports quickly.
set_tests_properties(random_tests PROPERTIES TIMEOUT 120)

# Present in the tree but never registered, so it had never been built or run.
# It covers concurrent nostr_init() and concurrent nostr_key_generate().
#
# POSIX only: the file uses pthread.h directly, which MSVC does not provide, and
# that is most likely why it was never wired up. test_random.c carries a shim so
# its concurrency case still runs on Windows; porting this one is left separate.
if(NOT WIN32)
    add_executable(test_thread_safety test_thread_safety.c)
    target_link_libraries(test_thread_safety nostr_static nostr_unity Threads::Threads)
    add_test(NAME thread_safety_tests COMMAND test_thread_safety)
    set_tests_properties(thread_safety_tests PROPERTIES TIMEOUT 180)
endif()

target_link_libraries(test_runner nostr_static nostr_unity)
target_compile_definitions(test_runner PRIVATE TEST_RUNNER_INCLUDED)

add_test(NAME unit_tests COMMAND test_runner)