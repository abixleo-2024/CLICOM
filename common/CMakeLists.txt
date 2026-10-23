# common/CMakeLists.txt
# CLICOM Common Library (libclicom_common)
#
# Contains: shared type definitions, protocol constants, logging, error codes.
# Dependencies: none (stdlib only).
# Linked by: client, server, tests, and the storage/security stub modules.

add_library(clicom_common STATIC
    src/clip_log.c
    src/clip_errors.c
    src/clip_protocol.c
    src/clip_net.c
    src/clip_crypto.c
    src/clip_telemetry.c
)

target_include_directories(clicom_common
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_BINARY_DIR}/include"   # generated clip_version.h
)

clicom_set_warnings(clicom_common)

if(WIN32)
    target_compile_definitions(clicom_common
        PRIVATE WIN32_LEAN_AND_MEAN
    )
    target_link_libraries(clicom_common
        PUBLIC ws2_32 bcrypt
    )
endif()
