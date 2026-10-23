# client/CMakeLists.txt
# CLICOM Client Executable (clicom)
#
# Phase 0: main.c only (scaffold, argument parsing, self-test).
# Phase 2+: network.c, channel.c, ptt.c, audio.c, history.c, cli.c, ...

add_executable(clicom
    src/main.c
    src/network.c
    src/clip_credentials.c
    src/clip_captions.c
    src/clip_notes_client.c
    src/clip_security_client.c
    src/clip_admin_client.c
)

target_include_directories(clicom
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/server/include"
        "${CMAKE_SOURCE_DIR}/transport/include"
        "${CMAKE_SOURCE_DIR}/audio/include"
        "${CMAKE_SOURCE_DIR}/speech/include"
        "${CMAKE_SOURCE_DIR}/security/include"
)

target_link_libraries(clicom
    PRIVATE clicom_common clicom_transport clicom_audio clicom_speech clicom_security crypt32 winmm
)

clicom_set_warnings(clicom)

# Installation rule (used by Phase 20 packaging)
install(TARGETS clicom
    RUNTIME DESTINATION bin
)
install(FILES "${CMAKE_SOURCE_DIR}/config/client.conf"
    DESTINATION etc/clicom
)
