cmake_minimum_required(VERSION 3.16)

add_executable(bench_runner
    bench_runner.c
    bench_key.c
    bench_crypto.c
    bench_event.c
    bench_encoding.c
    bench_memory.c
)

target_include_directories(bench_runner PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(bench_runner nostr_static)

add_custom_target(benchmark
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/bench_runner
    DEPENDS bench_runner
    COMMENT "Running performance benchmarks"
)

add_executable(profile_runner
    profile_runner.c
    bench_key.c
    bench_crypto.c
    bench_event.c
    bench_encoding.c
    bench_memory.c
)

target_include_directories(profile_runner PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(profile_runner nostr_static)

add_custom_target(profile
    COMMAND valgrind --tool=callgrind --callgrind-out-file=callgrind.out ${CMAKE_CURRENT_BINARY_DIR}/profile_runner
    DEPENDS profile_runner
    COMMENT "Profiling CPU usage with callgrind"
)

# Unix-only tools (use sys/resource.h, /proc, etc.)
if(NOT WIN32)
    add_executable(memory_analysis memory_analysis.c)
    target_include_directories(memory_analysis PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_libraries(memory_analysis nostr_static)

    # SIMD analysis only on x86/x86_64 (SSE2/AVX2 not available on ARM)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|i[3-6]86)")
        add_executable(simd_analysis simd_analysis.c)
        target_include_directories(simd_analysis PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../include
            ${CMAKE_CURRENT_SOURCE_DIR}
        )
        target_link_libraries(simd_analysis nostr_static)
        target_compile_options(simd_analysis PRIVATE -msse2 -mavx2)

        add_custom_target(simd-analysis
            COMMAND ${CMAKE_CURRENT_BINARY_DIR}/simd_analysis
            DEPENDS simd_analysis
            COMMENT "Analyzing SIMD optimization opportunities"
        )
    endif()

    add_custom_target(memory-analysis
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/memory_analysis
        DEPENDS memory_analysis
        COMMENT "Analyzing memory allocation patterns"
    )

endif()

add_executable(regression_test regression_test.c)
target_include_directories(regression_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(regression_test nostr_static)

add_custom_target(regression-test
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/regression_test
    DEPENDS regression_test
    COMMENT "Running performance regression tests"
)

add_custom_target(save-baseline
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/regression_test --save-baseline
    DEPENDS regression_test
    COMMENT "Saving performance baseline"
)