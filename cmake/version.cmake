# cmake/version.cmake
# Injects build-time metadata consumed by clip_version.h.in

# UTC build timestamp
string(TIMESTAMP CLICOM_BUILD_TIMESTAMP "%Y-%m-%dT%H:%M:%SZ" UTC)

# Target platform string
if(WIN32)
    set(CLICOM_TARGET_PLATFORM "Windows")
elseif(APPLE)
    set(CLICOM_TARGET_PLATFORM "macOS")
elseif(UNIX)
    set(CLICOM_TARGET_PLATFORM "Linux")
else()
    set(CLICOM_TARGET_PLATFORM "Unknown")
endif()

message(STATUS "CLICOM software version  : ${PROJECT_VERSION}")
message(STATUS "CLIP  protocol version   : ${CLIP_PROTOCOL_VERSION_MAJOR}.${CLIP_PROTOCOL_VERSION_MINOR}")
message(STATUS "Build timestamp          : ${CLICOM_BUILD_TIMESTAMP}")
message(STATUS "Target platform          : ${CLICOM_TARGET_PLATFORM}")
