# storage/CMakeLists.txt
# CLICOM Storage Module (clicom_storage)
#
# Phase 0: INTERFACE library — header declarations only.
# Phase 17: Add sqlite_backend.c; switch to STATIC. Link against SQLite3.

add_library(clicom_storage INTERFACE)

target_include_directories(clicom_storage
    INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

# storage.h includes clip_types.h and clip_errors.h from clicom_common.
# Propagate the dependency so any consumer of clicom_storage automatically
# gets clicom_common's include directories.
target_link_libraries(clicom_storage
    INTERFACE clicom_common
)
