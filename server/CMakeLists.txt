# server/CMakeLists.txt
# CLICOM Server Executable (clicom-server)
#
# Phase 0: main.c only (scaffold, argument parsing, self-test).
# Phase 2+: server.c, node_registry.c, channels.c, sessions.c,
#           ptt_arbiter.c, security_analyzer.c, admin.c, logger.c, ...

add_executable(clicom-server
    src/main.c
    src/server.c
    src/clients.c
    src/clip_identity.c
    src/clip_channels.c
    src/clip_sessions.c
    src/clip_connections.c
    src/clip_ptt.c
    src/clip_audio_seq.c
    src/clip_notes.c
    src/clip_security_db.c
    src/clip_admin_db.c
    src/clip_rate_limit.c
)

target_include_directories(clicom-server
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/transport/include"
        "${CMAKE_SOURCE_DIR}/security/include"
)

target_link_libraries(clicom-server
    PRIVATE clicom_common clicom_transport clicom_security sqlite3
)

clicom_set_warnings(clicom-server)

# Installation rule (used by Phase 20 packaging)
install(TARGETS clicom-server
    RUNTIME DESTINATION bin
)
install(FILES
    "${CMAKE_SOURCE_DIR}/config/server.conf"
    "${CMAKE_SOURCE_DIR}/config/security_rules.conf"
    DESTINATION etc/clicom
)
