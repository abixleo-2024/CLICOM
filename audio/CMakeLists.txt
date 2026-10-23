# audio/CMakeLists.txt
# CLICOM Audio Module (clicom_audio)
#
# Phase 9: Ring buffer, mock/WinMM device abstraction, audio engine.
# Phase 11: Swappable codecs (codec_null, codec_pcm, codec_opus) with libopus.

add_library(clicom_audio STATIC
    src/clip_audio_ring_buffer.c
    src/clip_audio_device.c
    src/clip_audio.c
    src/codec.c
    src/codec_null.c
    src/codec_pcm.c
    src/codec_opus.c
)

target_include_directories(clicom_audio
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/common/include"
)

target_link_libraries(clicom_audio
    PUBLIC
        clicom_common
        opus
    PRIVATE
        winmm
)
