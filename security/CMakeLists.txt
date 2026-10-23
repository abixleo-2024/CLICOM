# security/CMakeLists.txt
# CLICOM Security Module (clicom_security)
#
# Phase 0: INTERFACE library — header declarations only.
# Phase 15: Add rules_loader.c, analyzer.c; switch to STATIC.

add_library(clicom_security STATIC
    src/security_rules.c
    src/security_analyzer.c
    src/clip_admin.c
)

target_include_directories(clicom_security
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_SOURCE_DIR}/common/include"
)

target_link_libraries(clicom_security
    PUBLIC clicom_common crypto
)

clicom_set_warnings(clicom_security)
