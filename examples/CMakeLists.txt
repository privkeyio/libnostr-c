# Use static library on Windows to avoid DLL import library issues
if(WIN32)
    set(NOSTR_LIB_TARGET nostr_static)
else()
    set(NOSTR_LIB_TARGET nostr)
endif()

# Core examples (always available)
add_executable(basic_event basic_event.c)
add_dependencies(basic_event ${NOSTR_LIB_TARGET})
target_link_libraries(basic_event ${NOSTR_LIB_TARGET})

add_executable(key_management key_management.c)
add_dependencies(key_management ${NOSTR_LIB_TARGET})
target_link_libraries(key_management ${NOSTR_LIB_TARGET})

# Relay-dependent examples
if(NOSTR_FEATURE_RELAY)
    add_executable(publish_note publish_note.c)
    add_dependencies(publish_note ${NOSTR_LIB_TARGET})
    target_link_libraries(publish_note ${NOSTR_LIB_TARGET})

    add_executable(subscribe_events subscribe_events.c)
    add_dependencies(subscribe_events ${NOSTR_LIB_TARGET})
    target_link_libraries(subscribe_events ${NOSTR_LIB_TARGET})

    add_executable(relay_client relay_client.c)
    add_dependencies(relay_client ${NOSTR_LIB_TARGET})
    target_link_libraries(relay_client ${NOSTR_LIB_TARGET})
endif()

# NIP-specific examples
if(NOSTR_FEATURE_NIP13)
    add_executable(nip13_example nip13_example.c)
    add_dependencies(nip13_example ${NOSTR_LIB_TARGET})
    target_link_libraries(nip13_example ${NOSTR_LIB_TARGET})
endif()

if(NOSTR_FEATURE_NIP57)
    add_executable(zap_example zap_example.c)
    add_dependencies(zap_example ${NOSTR_LIB_TARGET})
    target_link_libraries(zap_example ${NOSTR_LIB_TARGET})
endif()

if(NOSTR_FEATURE_NIP59)
    add_executable(gift_wrap_demo gift_wrap_demo.c)
    add_dependencies(gift_wrap_demo ${NOSTR_LIB_TARGET})
    target_link_libraries(gift_wrap_demo ${NOSTR_LIB_TARGET})
endif()

if(NOSTR_FEATURE_NIP47)
    add_executable(wallet_connect_demo wallet_connect_demo_minimal.c)
    add_dependencies(wallet_connect_demo ${NOSTR_LIB_TARGET})
    target_link_libraries(wallet_connect_demo ${NOSTR_LIB_TARGET})
endif()

if(NOSTR_FEATURE_HD_KEYS)
    add_executable(hd_key_example hd_key_example.c)
    add_dependencies(hd_key_example ${NOSTR_LIB_TARGET})
    target_link_libraries(hd_key_example ${NOSTR_LIB_TARGET})
endif()