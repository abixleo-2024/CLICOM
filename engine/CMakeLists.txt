# engine/CMakeLists.txt
# CLICOM Native Engine Library

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    cmake_minimum_required(VERSION 3.25)
    project(clicom_engine
        VERSION 2.0.0
        DESCRIPTION "CLICOM Native Engine Foundation"
        LANGUAGES C
    )
    set(CMAKE_C_STANDARD 11)
    set(CMAKE_C_STANDARD_REQUIRED ON)
    set(CMAKE_C_EXTENSIONS OFF)
    enable_testing()
endif()

set(ENGINE_SOURCES
    src/clicom.c
    src/session.c
    src/audio_state.c
    src/engine_network.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)

set(ENGINE_HEADERS
    include/clicom.h
    src/engine_internal.h
)

# ── Shared Library (for Python ctypes and dynamic linking) ───────────────────
add_library(clicom_engine SHARED
    ${ENGINE_SOURCES}
    ${ENGINE_HEADERS}
)

target_include_directories(clicom_engine
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<INSTALL_INTERFACE:include>"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_SOURCE_DIR}/client/include"
        "${CMAKE_SOURCE_DIR}/common/include"
        "${CMAKE_SOURCE_DIR}/server/include"
        "${CMAKE_SOURCE_DIR}/transport/include"
        "${CMAKE_SOURCE_DIR}/audio/include"
        "${CMAKE_SOURCE_DIR}/speech/include"
        "${CMAKE_SOURCE_DIR}/security/include"
)

target_compile_definitions(clicom_engine
    PRIVATE
        CLICOM_EXPORTS
        CLICOM_BUILDING_DLL
)

target_link_libraries(clicom_engine
    PRIVATE
        clicom_common
        clicom_transport
        clicom_audio
        clicom_speech
        clicom_security
        sqlite3
        crypt32
        bcrypt
        ws2_32
        ssl
        crypto
        winmm
)

if(WIN32)
    target_compile_definitions(clicom_engine PRIVATE WIN32_LEAN_AND_MEAN)
endif()

# ── Static Library (for embedded C usage and static testing) ─────────────────
add_library(clicom_engine_static STATIC
    ${ENGINE_SOURCES}
    ${ENGINE_HEADERS}
)

target_include_directories(clicom_engine_static
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<INSTALL_INTERFACE:include>"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_SOURCE_DIR}/client/include"
        "${CMAKE_SOURCE_DIR}/common/include"
        "${CMAKE_SOURCE_DIR}/server/include"
        "${CMAKE_SOURCE_DIR}/transport/include"
        "${CMAKE_SOURCE_DIR}/audio/include"
        "${CMAKE_SOURCE_DIR}/speech/include"
        "${CMAKE_SOURCE_DIR}/security/include"
)

target_compile_definitions(clicom_engine_static
    PUBLIC
        CLICOM_STATIC
)

target_link_libraries(clicom_engine_static
    PUBLIC
        clicom_common
        clicom_transport
        clicom_audio
        clicom_speech
        clicom_security
        sqlite3
        crypt32
        bcrypt
        ws2_32
        ssl
        crypto
        winmm
)

if(WIN32)
    target_compile_definitions(clicom_engine_static PRIVATE WIN32_LEAN_AND_MEAN)
endif()

if(COMMAND clicom_set_warnings)
    clicom_set_warnings(clicom_engine)
    clicom_set_warnings(clicom_engine_static)
endif()

# ── Unit Tests ───────────────────────────────────────────────────────────────
if(BUILD_TESTING OR CLICOM_BUILD_TESTS OR (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR))
    add_executable(test_engine
        tests/test_engine.c
    )

    target_link_libraries(test_engine PRIVATE clicom_engine_static)
    target_include_directories(test_engine PRIVATE include src)

    add_test(NAME "Unit::Engine" COMMAND test_engine)
    set_tests_properties("Unit::Engine" PROPERTIES
        TIMEOUT 30
        WORKING_DIRECTORY "$<TARGET_FILE_DIR:test_engine>"
    )
    if(WIN32)
        set_tests_properties("Unit::Engine" PROPERTIES
            ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:C:/msys64/ucrt64/bin"
        )
    endif()
endif()
