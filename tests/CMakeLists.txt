# tests/CMakeLists.txt
# CLICOM Test Suite
#
# Phase 0 tests:
#   Unit::Version         — C unit test for version constants and enums
#   Startup::Client::*    — verify clicom executable starts and exits 0
#   Startup::Server::*    — verify clicom-server executable starts and exits 0

include_directories(${CMAKE_SOURCE_DIR}/audio/include)
include_directories(${CMAKE_SOURCE_DIR}/speech/include)
include_directories(${CMAKE_SOURCE_DIR}/security/include)

# ── Unit test: version constants (Phase 0) ───────────────────────────────
add_executable(test_version unit/test_version.c)
target_link_libraries(test_version PRIVATE clicom_common)
clicom_set_warnings(test_version)

add_test(NAME "Unit::Version" COMMAND test_version)
set_tests_properties("Unit::Version" PROPERTIES
    TIMEOUT 15
    WORKING_DIRECTORY "$<TARGET_FILE_DIR:test_version>"
)

# ── Unit test: protocol & framing (Phase 1) ──────────────────────────────
add_executable(test_protocol unit/test_protocol.c)
target_link_libraries(test_protocol PRIVATE clicom_common)
clicom_set_warnings(test_protocol)

add_test(NAME "Unit::Protocol" COMMAND test_protocol)
set_tests_properties("Unit::Protocol" PROPERTIES
    TIMEOUT 15
    WORKING_DIRECTORY "$<TARGET_FILE_DIR:test_protocol>"
)

# ── Integration test: networking (Phase 2) ───────────────────────────────
add_executable(test_network
    unit/test_network.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(test_network PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
)
target_link_libraries(test_network PRIVATE clicom_common clicom_transport clicom_audio clicom_speech clicom_security winmm sqlite3 crypt32 bcrypt ws2_32 ssl crypto)
clicom_set_warnings(test_network)

add_test(NAME "Integration::Network" COMMAND test_network)
set_tests_properties("Integration::Network" PROPERTIES
    TIMEOUT 20
    WORKING_DIRECTORY "$<TARGET_FILE_DIR:test_network>"
)

# ── Integration test: authentication & identity (Phase 3) ────────────────
add_executable(test_auth
    unit/test_auth.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(test_auth PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
)
target_link_libraries(test_auth PRIVATE clicom_common clicom_transport clicom_audio clicom_speech clicom_security winmm sqlite3 crypt32 bcrypt ws2_32 ssl crypto)
clicom_set_warnings(test_auth)

add_test(NAME "Integration::Auth" COMMAND test_auth)
set_tests_properties("Integration::Auth" PROPERTIES
    TIMEOUT 20
    WORKING_DIRECTORY "$<TARGET_FILE_DIR:test_auth>"
)

# ── Integration test: channels & communication sessions (Phase 4) ────────
add_executable(test_channels
    unit/test_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(test_channels PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
)
target_link_libraries(test_channels PRIVATE clicom_common clicom_transport clicom_audio clicom_speech clicom_security winmm sqlite3 crypt32 bcrypt ws2_32 ssl crypto)
clicom_set_warnings(test_channels)

add_test(NAME "Integration::Channels" COMMAND test_channels)
set_tests_properties("Integration::Channels" PROPERTIES
    TIMEOUT 25
    WORKING_DIRECTORY "$<TARGET_FILE_DIR:test_channels>"
)

# ── Integration test: online discovery & connection requests (Phase 5) ───
add_executable(test_connections
    unit/test_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(test_connections PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
)
target_link_libraries(test_connections PRIVATE clicom_common clicom_transport clicom_audio clicom_speech clicom_security winmm sqlite3 crypt32 bcrypt ws2_32 ssl crypto)
clicom_set_warnings(test_connections)

add_test(NAME "Integration::Connections" COMMAND test_connections)
set_tests_properties("Integration::Connections" PROPERTIES
    TIMEOUT 25
    WORKING_DIRECTORY "$<TARGET_FILE_DIR:test_connections>"
)

# ── Standalone Live Demonstration (Phase 5) ───────────────────────────────
add_executable(demo_connections
    demo_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(demo_connections PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
)
target_link_libraries(demo_connections PRIVATE clicom_common clicom_transport clicom_audio clicom_speech clicom_security winmm sqlite3 crypt32 bcrypt ws2_32 ssl crypto)
clicom_set_warnings(demo_connections)

# ── Integration test: communication session binding (Phase 6) ─────────────
add_executable(test_session_binding
    unit/test_session_binding.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(test_session_binding PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
)
target_link_libraries(test_session_binding PRIVATE clicom_common clicom_transport clicom_audio clicom_speech clicom_security winmm sqlite3 crypt32 bcrypt ws2_32 ssl crypto)
clicom_set_warnings(test_session_binding)

add_test(NAME "Integration::Sessions" COMMAND test_session_binding)
set_tests_properties("Integration::Sessions" PROPERTIES
    TIMEOUT 25
    WORKING_DIRECTORY "$<TARGET_FILE_DIR:test_session_binding>"
)

# ── Standalone Live Demonstration (Phase 6) ───────────────────────────────
add_executable(demo_sessions
    demo_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(demo_sessions PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
)
target_link_libraries(demo_sessions PRIVATE clicom_common clicom_transport clicom_audio clicom_speech clicom_security winmm sqlite3 crypt32 bcrypt ws2_32 ssl crypto)
clicom_set_warnings(demo_sessions)

# ── Integration startup tests ─────────────────────────────────────────────
# Use $<TARGET_FILE:...> so CTest resolves the correct executable path
# for both single-config (Ninja/Make) and multi-config (Visual Studio) builds.

if(TARGET clicom)
    add_test(NAME "Startup::Client::Version"
        COMMAND "$<TARGET_FILE:clicom>" --version)
    set_tests_properties("Startup::Client::Version" PROPERTIES
        TIMEOUT 15
        WORKING_DIRECTORY "$<TARGET_FILE_DIR:clicom>"
    )

    add_test(NAME "Startup::Client::SelfTest"
        COMMAND "$<TARGET_FILE:clicom>" --test)
    set_tests_properties("Startup::Client::SelfTest" PROPERTIES
        TIMEOUT 15
        WORKING_DIRECTORY "$<TARGET_FILE_DIR:clicom>"
    )
endif()

if(TARGET clicom-server)
    add_test(NAME "Startup::Server::Version"
        COMMAND "$<TARGET_FILE:clicom-server>" --version)
    set_tests_properties("Startup::Server::Version" PROPERTIES
        TIMEOUT 15
        WORKING_DIRECTORY "$<TARGET_FILE_DIR:clicom-server>"
    )

    add_test(NAME "Startup::Server::SelfTest"
        COMMAND "$<TARGET_FILE:clicom-server>" --test)
    set_tests_properties("Startup::Server::SelfTest" PROPERTIES
        TIMEOUT 15
        WORKING_DIRECTORY "$<TARGET_FILE_DIR:clicom-server>"
    )
endif()

# ── Integration test: TLS 1.3 Secure Transport (Phase 7) ─────────────────
add_executable(test_tls
    unit/test_tls.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(test_tls PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
)
target_link_libraries(test_tls PRIVATE clicom_common clicom_transport clicom_audio clicom_speech clicom_security winmm sqlite3 crypt32 bcrypt ws2_32 ssl crypto)
clicom_set_warnings(test_tls)

add_test(NAME "Integration::TLS" COMMAND test_tls)
set_tests_properties("Integration::TLS" PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Standalone Live Demonstration (Phase 7) ───────────────────────────────
add_executable(demo_tls
    demo_tls.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(demo_tls PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
)
target_link_libraries(demo_tls PRIVATE clicom_common clicom_transport clicom_audio clicom_speech clicom_security winmm sqlite3 crypt32 bcrypt ws2_32 ssl crypto)
clicom_set_warnings(demo_tls)

# ── Integration test: Push-to-Talk (PTT) Floor Control (Phase 8) ────────
add_executable(test_ptt
    unit/test_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(test_ptt PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
)
target_link_libraries(test_ptt PRIVATE clicom_common clicom_transport clicom_audio clicom_speech clicom_security winmm sqlite3 crypt32 bcrypt ws2_32 ssl crypto)
clicom_set_warnings(test_ptt)

add_test(NAME "Integration::PTT" COMMAND test_ptt)
set_tests_properties("Integration::PTT" PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Standalone Live Demonstration (Phase 8) ───────────────────────────────
add_executable(demo_ptt
    demo_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(demo_ptt PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
)
target_link_libraries(demo_ptt PRIVATE clicom_common clicom_transport clicom_audio clicom_speech clicom_security winmm sqlite3 crypt32 bcrypt ws2_32 ssl crypto)
clicom_set_warnings(demo_ptt)

# ── Unit test: Audio Subsystem (Phase 9) ──────────────────────────────────
add_executable(test_audio
    unit/test_audio.c
)
target_include_directories(test_audio PRIVATE
    ${CMAKE_SOURCE_DIR}/audio/include
)
target_link_libraries(test_audio PRIVATE clicom_common clicom_audio clicom_speech winmm)
clicom_set_warnings(test_audio)

add_test(NAME "Unit::Audio" COMMAND test_audio)
set_tests_properties("Unit::Audio" PROPERTIES
    TIMEOUT 20
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Integration test: Network Audio Transport over TLS (Phase 10) ────────
add_executable(test_audio_transport
    unit/test_audio_transport.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(test_audio_transport PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
    ${CMAKE_SOURCE_DIR}/audio/include
)
target_link_libraries(test_audio_transport PRIVATE
    clicom_common clicom_transport clicom_audio clicom_speech clicom_security sqlite3 crypt32 bcrypt ws2_32 ssl crypto winmm
)
clicom_set_warnings(test_audio_transport)

add_test(NAME "Integration::AudioTransport" COMMAND test_audio_transport)
set_tests_properties("Integration::AudioTransport" PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Unit test: Audio Codecs (Phase 11) ────────────────────────────────────
add_executable(test_codec
    unit/test_codec.c
)
target_include_directories(test_codec PRIVATE
    ${CMAKE_SOURCE_DIR}/audio/include
)
target_link_libraries(test_codec PRIVATE
    clicom_common clicom_audio clicom_speech opus
)
clicom_set_warnings(test_codec)

add_test(NAME "Unit::Codec" COMMAND test_codec)
set_tests_properties("Unit::Codec" PROPERTIES
    TIMEOUT 20
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Integration test: Opus Audio Transport over TLS 1.3 (Phase 11) ────────
add_executable(test_opus_transport
    unit/test_opus_transport.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(test_opus_transport PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
    ${CMAKE_SOURCE_DIR}/audio/include
)
target_link_libraries(test_opus_transport PRIVATE
    clicom_common clicom_transport clicom_audio clicom_speech clicom_security opus sqlite3 crypt32 bcrypt ws2_32 ssl crypto winmm
)
clicom_set_warnings(test_opus_transport)

add_test(NAME "Integration::OpusTransport" COMMAND test_opus_transport)
set_tests_properties("Integration::OpusTransport" PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Unit test: SpeechAnalyzer & Audio Pipeline (Phase 12) ────────────────
add_executable(test_speech_analyzer
    unit/test_speech_analyzer.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
)
target_include_directories(test_speech_analyzer PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
    ${CMAKE_SOURCE_DIR}/audio/include
    ${CMAKE_SOURCE_DIR}/speech/include
)
target_link_libraries(test_speech_analyzer PRIVATE
    clicom_common clicom_transport clicom_audio clicom_speech clicom_security opus sqlite3 crypt32 bcrypt ws2_32 ssl crypto winmm
)
clicom_set_warnings(test_speech_analyzer)

add_test(NAME "Unit::SpeechAnalyzer" COMMAND test_speech_analyzer)
set_tests_properties("Unit::SpeechAnalyzer" PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Unit test: Live Captions UI & Buffer (Phase 13) ──────────────────────
add_executable(test_captions
    unit/test_captions.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_captions.c
)
target_include_directories(test_captions PRIVATE
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/speech/include
    ${CMAKE_SOURCE_DIR}/common/include
)
target_link_libraries(test_captions PRIVATE
    clicom_common clicom_speech winmm
)
clicom_set_warnings(test_captions)

add_test(NAME "Unit::Captions" COMMAND test_captions)
set_tests_properties("Unit::Captions" PROPERTIES
    TIMEOUT 20
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Unit test: Notes & Session Logs (Phase 14) ───────────────────────────
add_executable(test_notes
    unit/test_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_captions.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_notes_client.c
)
target_include_directories(test_notes PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
    ${CMAKE_SOURCE_DIR}/audio/include
    ${CMAKE_SOURCE_DIR}/speech/include
    ${CMAKE_SOURCE_DIR}/common/include
)
target_link_libraries(test_notes PRIVATE
    clicom_common clicom_transport clicom_audio clicom_speech clicom_security opus sqlite3 crypt32 bcrypt ws2_32 ssl crypto winmm
)
clicom_set_warnings(test_notes)

add_test(NAME "Unit::Notes" COMMAND test_notes)
set_tests_properties("Unit::Notes" PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Unit test: Security Keyword Analysis (Phase 15) ──────────────────────
add_executable(test_security
    unit/test_security.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_captions.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_notes_client.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_security_client.c
)
target_include_directories(test_security PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
    ${CMAKE_SOURCE_DIR}/audio/include
    ${CMAKE_SOURCE_DIR}/speech/include
    ${CMAKE_SOURCE_DIR}/security/include
    ${CMAKE_SOURCE_DIR}/common/include
)
target_link_libraries(test_security PRIVATE
    clicom_common clicom_transport clicom_audio clicom_speech clicom_security opus sqlite3 crypt32 bcrypt ws2_32 ssl crypto winmm
)
clicom_set_warnings(test_security)

add_test(NAME "Unit::Security" COMMAND test_security)
set_tests_properties("Unit::Security" PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Unit test: Admin Alerts & Actions (Phase 16) ─────────────────────────
add_executable(test_admin
    unit/test_admin.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_captions.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_notes_client.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_security_client.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_admin_client.c
)
target_include_directories(test_admin PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
    ${CMAKE_SOURCE_DIR}/audio/include
    ${CMAKE_SOURCE_DIR}/speech/include
    ${CMAKE_SOURCE_DIR}/security/include
    ${CMAKE_SOURCE_DIR}/common/include
)
target_link_libraries(test_admin PRIVATE
    clicom_common clicom_transport clicom_audio clicom_speech clicom_security opus sqlite3 crypt32 bcrypt ws2_32 ssl crypto winmm
)
clicom_set_warnings(test_admin)

add_test(NAME "Unit::Admin" COMMAND test_admin)
set_tests_properties("Unit::Admin" PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Stress, Reliability & Security Testing (Phase 19) ───────────────────
add_executable(test_stress_security
    unit/test_stress_security.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_captions.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_notes_client.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_security_client.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_admin_client.c
)
target_include_directories(test_stress_security PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
    ${CMAKE_SOURCE_DIR}/audio/include
    ${CMAKE_SOURCE_DIR}/speech/include
    ${CMAKE_SOURCE_DIR}/security/include
    ${CMAKE_SOURCE_DIR}/common/include
)
target_link_libraries(test_stress_security PRIVATE
    clicom_common clicom_transport clicom_audio clicom_speech clicom_security opus sqlite3 crypt32 bcrypt ws2_32 ssl crypto winmm
)
clicom_set_warnings(test_stress_security)

add_test(NAME "Integration::StressSecurity" COMMAND test_stress_security)
set_tests_properties("Integration::StressSecurity" PROPERTIES
    TIMEOUT 60
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Unit test: telemetry engine (Truthful Metrics) ───────────────────────
add_executable(test_telemetry unit/test_telemetry.c)
target_link_libraries(test_telemetry PRIVATE clicom_common)
clicom_set_warnings(test_telemetry)

add_test(NAME "Unit::Telemetry" COMMAND test_telemetry)
set_tests_properties("Unit::Telemetry" PROPERTIES
    TIMEOUT 15
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Integration test: Phase 2A Server Integration ──────────────────────────
add_executable(test_phase2a_server
    unit/test_phase2a_server.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/network.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_credentials.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_captions.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_notes_client.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_security_client.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_admin_client.c
)
target_include_directories(test_phase2a_server PRIVATE
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
    ${CMAKE_SOURCE_DIR}/audio/include
    ${CMAKE_SOURCE_DIR}/speech/include
    ${CMAKE_SOURCE_DIR}/security/include
    ${CMAKE_SOURCE_DIR}/common/include
)
target_link_libraries(test_phase2a_server PRIVATE
    clicom_common clicom_transport clicom_audio clicom_speech clicom_security opus sqlite3 crypt32 bcrypt ws2_32 ssl crypto winmm
)
clicom_set_warnings(test_phase2a_server)

add_test(NAME "Integration::Phase2AServer" COMMAND test_phase2a_server)
set_tests_properties("Integration::Phase2AServer" PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Integration test: Phase 3A Real Voice Transport ─────────────────────────
add_executable(test_phase3a_voice
    unit/test_phase3a_voice.c
    ${CMAKE_SOURCE_DIR}/server/src/server.c
    ${CMAKE_SOURCE_DIR}/server/src/clients.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_identity.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_channels.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_sessions.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_connections.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_ptt.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_audio_seq.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_notes.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_security_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_admin_db.c
    ${CMAKE_SOURCE_DIR}/server/src/clip_rate_limit.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_captions.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_notes_client.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_security_client.c
    ${CMAKE_SOURCE_DIR}/client/src/clip_admin_client.c
)
target_include_directories(test_phase3a_voice PRIVATE
    ${CMAKE_SOURCE_DIR}/engine/include
    ${CMAKE_SOURCE_DIR}/engine/src
    ${CMAKE_SOURCE_DIR}/server/include
    ${CMAKE_SOURCE_DIR}/client/include
    ${CMAKE_SOURCE_DIR}/transport/include
    ${CMAKE_SOURCE_DIR}/audio/include
    ${CMAKE_SOURCE_DIR}/speech/include
    ${CMAKE_SOURCE_DIR}/security/include
    ${CMAKE_SOURCE_DIR}/common/include
)
target_compile_definitions(test_phase3a_voice PRIVATE CLICOM_STATIC)
target_link_libraries(test_phase3a_voice PRIVATE
    clicom_engine_static clicom_common clicom_transport clicom_audio clicom_speech clicom_security opus sqlite3 crypt32 bcrypt ws2_32 ssl crypto winmm
)
clicom_set_warnings(test_phase3a_voice)

add_test(NAME "Integration::Phase3AVoice" COMMAND test_phase3a_voice)
set_tests_properties("Integration::Phase3AVoice" PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# ── Windows CTest Runtime Environment ─────────────────────────────────────
# Ensure all CTest test cases can resolve UCRT64 toolchain runtime DLLs
# (OpenSSL, Opus, SQLite3) when ctest is executed in a clean shell environment.
if(WIN32)
    set_tests_properties(
        "Unit::Version"
        "Unit::Protocol"
        "Unit::Telemetry"
        "Integration::Network"
        "Integration::Auth"
        "Integration::Channels"
        "Integration::Connections"
        "Integration::Sessions"
        "Startup::Client::Version"
        "Startup::Client::SelfTest"
        "Startup::Server::Version"
        "Startup::Server::SelfTest"
        "Integration::TLS"
        "Integration::PTT"
        "Unit::Audio"
        "Integration::AudioTransport"
        "Unit::Codec"
        "Integration::OpusTransport"
        "Unit::SpeechAnalyzer"
        "Unit::Captions"
        "Unit::Notes"
        "Unit::Security"
        "Unit::Admin"
        "Integration::StressSecurity"
        "Integration::Phase2AServer"
        "Integration::Phase3AVoice"
        PROPERTIES ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:C:/msys64/ucrt64/bin"
    )
endif()


