# speech/CMakeLists.txt
# CLICOM Speech Module (clicom_speech)
#
# Phase 12: Static library with SpeechAnalyzer abstraction, SpeechBuffer,
#           null adapter, and deterministic mock adapter.

add_library(clicom_speech STATIC
    src/speech_analyzer.c
    src/speech_buffer.c
    src/speech_null.c
    src/speech_mock.c
)

target_include_directories(clicom_speech
    PUBLIC  "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_SOURCE_DIR}/common/include"
)

target_link_libraries(clicom_speech
    PUBLIC clicom_common
)

clicom_set_warnings(clicom_speech)
