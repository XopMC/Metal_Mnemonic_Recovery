cmake_minimum_required(VERSION 3.22)

if(NOT APPLE)
    message(FATAL_ERROR
        "Metal_Mnemonic_Recovery is Metal-only and supports macOS with Metal. "
        "Use the macOS preset on a Darwin host."
    )
endif()
project(Metal_Mnemonic_Recovery VERSION 1.0.0 LANGUAGES C CXX OBJCXX)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR
        "In-source builds are not supported. Use an out-of-source build directory, "
        "for example via 'cmake --preset macos-metal-release'."
    )
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)
find_program(CMR_XCRUN_EXECUTABLE xcrun REQUIRED)
execute_process(
    COMMAND ${CMR_XCRUN_EXECUTABLE} --find metal
    RESULT_VARIABLE CMR_METAL_FIND_RESULT
    OUTPUT_VARIABLE CMR_METAL_COMPILER
    ERROR_VARIABLE CMR_METAL_FIND_ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT CMR_METAL_FIND_RESULT EQUAL 0 OR CMR_METAL_COMPILER STREQUAL "")
    message(FATAL_ERROR
        "Failed to locate the Metal compiler via xcrun --find metal. "
        "Install the Metal toolchain in Xcode Command Line Tools.\n${CMR_METAL_FIND_ERROR}"
    )
endif()
execute_process(
    COMMAND ${CMR_XCRUN_EXECUTABLE} --find metallib
    RESULT_VARIABLE CMR_METALLIB_FIND_RESULT
    OUTPUT_VARIABLE CMR_METALLIB_TOOL
    ERROR_VARIABLE CMR_METALLIB_FIND_ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT CMR_METALLIB_FIND_RESULT EQUAL 0 OR CMR_METALLIB_TOOL STREQUAL "")
    message(FATAL_ERROR
        "Failed to locate the metallib tool via xcrun --find metallib. "
        "Install the Metal toolchain in Xcode Command Line Tools.\n${CMR_METALLIB_FIND_ERROR}"
    )
endif()

set(METAL_MNEMONIC_RECOVERY_SOURCES
    src/app/main.cpp
    src/app/recovery_cli.cpp
    src/crypto/filter.cpp
    src/macos/recovery_macos.mm
    src/recovery/derivation_program.cpp
    src/recovery/found_record_formatter.cpp
    src/recovery/secp_precompute_load.cpp
    third_party/hash/sha256.cpp
)

set(SECP_PRECOMPUTE_BLOB ${CMAKE_CURRENT_BINARY_DIR}/generated/secp-precompute-v1.bin)

add_executable(Metal_Mnemonic_Recovery_secp_blob_generator
    tools/generate_secp_precompute_blob.cpp
    src/recovery/secp_precompute_load.cpp
    src/recovery/secp_precompute_build.cpp
)
target_include_directories(Metal_Mnemonic_Recovery_secp_blob_generator PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/hash
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/secp256k1
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ed25519
)
target_compile_options(Metal_Mnemonic_Recovery_secp_blob_generator PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-O3>
)

add_custom_command(
    OUTPUT ${SECP_PRECOMPUTE_BLOB}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/generated
    COMMAND $<TARGET_FILE:Metal_Mnemonic_Recovery_secp_blob_generator> ${SECP_PRECOMPUTE_BLOB}
    DEPENDS Metal_Mnemonic_Recovery_secp_blob_generator
    VERBATIM
)
add_custom_target(Metal_Mnemonic_Recovery_secp_blob DEPENDS ${SECP_PRECOMPUTE_BLOB})

add_executable(Metal_Mnemonic_Recovery ${METAL_MNEMONIC_RECOVERY_SOURCES})

target_include_directories(Metal_Mnemonic_Recovery PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/hash
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/secp256k1
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ed25519
)

target_link_libraries(Metal_Mnemonic_Recovery PRIVATE Threads::Threads)
target_compile_options(Metal_Mnemonic_Recovery PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-O3>
    $<$<COMPILE_LANGUAGE:C>:-O3>
    $<$<COMPILE_LANGUAGE:OBJCXX>:-O3>
    $<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>
)

find_library(METAL_FRAMEWORK Metal REQUIRED)
find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)
target_link_libraries(Metal_Mnemonic_Recovery PRIVATE
    ${METAL_FRAMEWORK}
    ${FOUNDATION_FRAMEWORK}
)

set(METAL_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/metal/ChecksumKernels.metal
    ${CMAKE_CURRENT_SOURCE_DIR}/src/metal/RecoveryEvalSecp.metal
    ${CMAKE_CURRENT_SOURCE_DIR}/src/metal/RecoveryEvalEd25519.metal
)
set(METAL_AIRS
    ${CMAKE_CURRENT_BINARY_DIR}/ChecksumKernels.air
    ${CMAKE_CURRENT_BINARY_DIR}/RecoveryEvalSecp.air
    ${CMAKE_CURRENT_BINARY_DIR}/RecoveryEvalEd25519.air
)
set(METAL_LIB ${CMAKE_CURRENT_BINARY_DIR}/ChecksumKernels.metallib)

set(_metal_compile_commands)
list(APPEND _metal_compile_commands
    COMMAND ${CMR_XCRUN_EXECUTABLE} metal -std=metal3.1 -I ${CMAKE_CURRENT_SOURCE_DIR}/include -c ${CMAKE_CURRENT_SOURCE_DIR}/src/metal/ChecksumKernels.metal -o ${CMAKE_CURRENT_BINARY_DIR}/ChecksumKernels.air
    COMMAND ${CMR_XCRUN_EXECUTABLE} metal -std=metal3.1 -I ${CMAKE_CURRENT_SOURCE_DIR} -I ${CMAKE_CURRENT_SOURCE_DIR}/include -I ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ed25519 -c ${CMAKE_CURRENT_SOURCE_DIR}/src/metal/RecoveryEvalSecp.metal -o ${CMAKE_CURRENT_BINARY_DIR}/RecoveryEvalSecp.air
    COMMAND ${CMR_XCRUN_EXECUTABLE} metal -std=metal3.1 -I ${CMAKE_CURRENT_SOURCE_DIR} -I ${CMAKE_CURRENT_SOURCE_DIR}/include -I ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ed25519 -c ${CMAKE_CURRENT_SOURCE_DIR}/src/metal/RecoveryEvalEd25519.metal -o ${CMAKE_CURRENT_BINARY_DIR}/RecoveryEvalEd25519.air
    COMMAND ${CMR_XCRUN_EXECUTABLE} metallib ${METAL_AIRS} -o ${METAL_LIB}
)

add_custom_command(
    OUTPUT ${METAL_LIB}
    ${_metal_compile_commands}
    DEPENDS
        ${METAL_SOURCES}
        ${CMAKE_CURRENT_SOURCE_DIR}/include/metal/RecoveryCryptoCommon.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/metal/RecoveryMetalTypes.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/metal/RecoveryEvalSecp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/metal/RecoveryEvalEd25519.h
    VERBATIM
)
add_custom_target(Metal_Mnemonic_Recovery_metallib DEPENDS ${METAL_LIB})
add_dependencies(Metal_Mnemonic_Recovery Metal_Mnemonic_Recovery_metallib)
add_dependencies(Metal_Mnemonic_Recovery Metal_Mnemonic_Recovery_secp_blob)
set_target_properties(Metal_Mnemonic_Recovery PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
add_custom_command(TARGET Metal_Mnemonic_Recovery POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${METAL_LIB} $<TARGET_FILE_DIR:Metal_Mnemonic_Recovery>/ChecksumKernels.metallib
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${SECP_PRECOMPUTE_BLOB} $<TARGET_FILE_DIR:Metal_Mnemonic_Recovery>/secp-precompute-v1.bin
    VERBATIM
)
install(TARGETS Metal_Mnemonic_Recovery RUNTIME DESTINATION bin)
install(FILES ${METAL_LIB} DESTINATION bin RENAME ChecksumKernels.metallib)
install(FILES ${SECP_PRECOMPUTE_BLOB} DESTINATION bin RENAME secp-precompute-v1.bin)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt
    ${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md
    ${CMAKE_CURRENT_SOURCE_DIR}/RESPONSIBLE_USE.md
    ${CMAKE_CURRENT_SOURCE_DIR}/SECURITY.md
    ${CMAKE_CURRENT_SOURCE_DIR}/SUPPORT.md
    ${CMAKE_CURRENT_SOURCE_DIR}/CHANGELOG.md
    ${CMAKE_CURRENT_SOURCE_DIR}/CITATION.cff
    ${CMAKE_CURRENT_SOURCE_DIR}/VALIDATION.md
    ${CMAKE_CURRENT_SOURCE_DIR}/BENCHMARKS.md
    ${CMAKE_CURRENT_SOURCE_DIR}/RELEASE_CHECKLIST.md
    DESTINATION .
)
install(DIRECTORY
    ${CMAKE_CURRENT_SOURCE_DIR}/docs
    ${CMAKE_CURRENT_SOURCE_DIR}/examples
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts
    ${CMAKE_CURRENT_SOURCE_DIR}/tests
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    ${CMAKE_CURRENT_SOURCE_DIR}/support
    ${CMAKE_CURRENT_SOURCE_DIR}/assets
    DESTINATION .
)

enable_testing()
add_test(
    NAME Metal_Mnemonic_Recovery.help
    COMMAND $<TARGET_FILE:Metal_Mnemonic_Recovery> -help
)
add_executable(Metal_Mnemonic_Recovery_derivation_program
    tests/derivation_program.cpp
    src/recovery/derivation_program.cpp
)
target_include_directories(Metal_Mnemonic_Recovery_derivation_program PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_options(Metal_Mnemonic_Recovery_derivation_program PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-O3>
)
add_test(
    NAME Metal_Mnemonic_Recovery.derivation_program
    COMMAND $<TARGET_FILE:Metal_Mnemonic_Recovery_derivation_program>
)
add_executable(Metal_Mnemonic_Recovery_metal_abi
    tests/metal_abi_layout.cpp
)
target_include_directories(Metal_Mnemonic_Recovery_metal_abi PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_options(Metal_Mnemonic_Recovery_metal_abi PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-O3>
)
add_test(
    NAME Metal_Mnemonic_Recovery.metal_abi_layout
    COMMAND $<TARGET_FILE:Metal_Mnemonic_Recovery_metal_abi>
)
add_executable(Metal_Mnemonic_Recovery_secp_precompute
    tests/secp_precompute.cpp
    src/recovery/secp_precompute_load.cpp
    src/recovery/secp_precompute_build.cpp
)
target_include_directories(Metal_Mnemonic_Recovery_secp_precompute PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/hash
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/secp256k1
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ed25519
)
target_compile_options(Metal_Mnemonic_Recovery_secp_precompute PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-O3>
)
add_test(
    NAME Metal_Mnemonic_Recovery.secp_precompute
    COMMAND $<TARGET_FILE:Metal_Mnemonic_Recovery_secp_precompute>
)
add_executable(Metal_Mnemonic_Recovery_found_record_formatter
    tests/found_record_formatter.cpp
    src/recovery/found_record_formatter.cpp
    third_party/hash/sha256.cpp
)
target_include_directories(Metal_Mnemonic_Recovery_found_record_formatter PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/hash
)
target_compile_options(Metal_Mnemonic_Recovery_found_record_formatter PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-O3>
)
target_link_libraries(Metal_Mnemonic_Recovery_found_record_formatter PRIVATE
    Threads::Threads
)
add_test(
    NAME Metal_Mnemonic_Recovery.found_record_formatter
    COMMAND $<TARGET_FILE:Metal_Mnemonic_Recovery_found_record_formatter>
)
add_test(
    NAME Metal_Mnemonic_Recovery.validation_macos_mainline
    COMMAND ${CMAKE_COMMAND} -E env
        CMR_EXE=$<TARGET_FILE:Metal_Mnemonic_Recovery>
        CMR_SKIP_EXPERIMENTAL=0
        bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate_release_macos.sh
)
add_test(
    NAME Metal_Mnemonic_Recovery.no_fallback_macos
    COMMAND ${CMAKE_COMMAND} -E env
        CMR_EXE=$<TARGET_FILE:Metal_Mnemonic_Recovery>
        bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_fallback_macos.sh
)
add_test(
    NAME Metal_Mnemonic_Recovery.unified_missing_acceptance_macos
    COMMAND ${CMAKE_COMMAND} -E env
        CMR_EXE=$<TARGET_FILE:Metal_Mnemonic_Recovery>
        bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/unified_missing_acceptance_macos.sh
)
add_test(
    NAME Metal_Mnemonic_Recovery.benchmark_smoke_macos
    COMMAND ${CMAKE_COMMAND} -E env
        CMR_EXE=$<TARGET_FILE:Metal_Mnemonic_Recovery>
        bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/benchmark_smoke_macos.sh
)
