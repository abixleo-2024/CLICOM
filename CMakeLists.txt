cmake_minimum_required(VERSION 3.25)

# ============================================================
#  CLICOM — CLI Communication System
#  Root CMakeLists.txt
#
#  Software version : 2.0.0   (semantic versioning for releases)
#  Protocol version : 1.0     (separate; governs wire compatibility)
#
#  These two versions are intentionally independent.
#  Protocol changes are documented in docs/PROTOCOL_CHANGELOG.md.
#  Never conflate software version with protocol version.
# ============================================================

project(CLICOM
    VERSION     2.0.0
    DESCRIPTION "CLICOM - CLI Communication System"
    LANGUAGES   C
)

# ── C Standard ──────────────────────────────────────────────────────────
set(CMAKE_C_STANDARD          11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS        OFF)

# ── Protocol version (separate from CMake project version) ──────────────
# Increment MAJOR on any breaking wire change.
# Increment MINOR on backward-compatible additions.
set(CLIP_PROTOCOL_VERSION_MAJOR 1)
set(CLIP_PROTOCOL_VERSION_MINOR 0)

# ── CMake helpers ────────────────────────────────────────────────────────
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(version)
include(CompilerWarnings)

# ── Build options ────────────────────────────────────────────────────────
option(CLICOM_BUILD_CLIENT "Build the clicom client executable"  ON)
option(CLICOM_BUILD_SERVER "Build the clicom-server executable"  ON)
option(CLICOM_BUILD_TESTS  "Build the test suite"                ON)

# ── Generate version header ──────────────────────────────────────────────
# clip_version.h is generated into the build directory at configure time.
# It is NOT committed to version control.
configure_file(
    "${CMAKE_SOURCE_DIR}/cmake/clip_version.h.in"
    "${CMAKE_BINARY_DIR}/include/clip_version.h"
    @ONLY
)

# Make the generated header available to all targets without
# each target explicitly adding the build include directory.
include_directories("${CMAKE_BINARY_DIR}/include")

# ── Subdirectories ───────────────────────────────────────────────────────
add_subdirectory(common)
add_subdirectory(transport)

if(CLICOM_BUILD_CLIENT)
    add_subdirectory(client)
endif()

if(CLICOM_BUILD_SERVER)
    add_subdirectory(server)
endif()

if(CLICOM_BUILD_TESTS)
    enable_testing()
endif()

# Stub module libraries (Phase 0: INTERFACE/header-only)
add_subdirectory(audio)
add_subdirectory(speech)
add_subdirectory(storage)
add_subdirectory(security)
add_subdirectory(engine)

if(CLICOM_BUILD_TESTS)
    add_subdirectory(tests)
endif()

# ── Install: config files ────────────────────────────────────────────────
install(DIRECTORY config/
    DESTINATION etc/clicom
    FILES_MATCHING PATTERN "*.conf"
)

# ── Configuration summary ────────────────────────────────────────────────
message(STATUS "")
message(STATUS "╔══════════════════════════════════════════╗")
message(STATUS "║         CLICOM Build Configuration       ║")
message(STATUS "╠══════════════════════════════════════════╣")
message(STATUS "║  Software version : ${PROJECT_VERSION}              ║")
message(STATUS "║  Protocol version : ${CLIP_PROTOCOL_VERSION_MAJOR}.${CLIP_PROTOCOL_VERSION_MINOR}                  ║")
message(STATUS "║  C standard       : C${CMAKE_C_STANDARD}                      ║")
message(STATUS "║  Build type       : ${CMAKE_BUILD_TYPE}              ║")
message(STATUS "║  Build client     : ${CLICOM_BUILD_CLIENT}                  ║")
message(STATUS "║  Build server     : ${CLICOM_BUILD_SERVER}                  ║")
message(STATUS "║  Build tests      : ${CLICOM_BUILD_TESTS}                   ║")
message(STATUS "╚══════════════════════════════════════════╝")
message(STATUS "")
