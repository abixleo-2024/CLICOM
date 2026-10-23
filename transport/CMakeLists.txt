# transport/CMakeLists.txt
# CLICOM Transport & TLS 1.3 Abstraction Library

add_library(clicom_transport STATIC
    src/clip_tls.c
    src/clip_transport.c
)

target_include_directories(clicom_transport
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/common/include"
        "${CMAKE_BINARY_DIR}/include"
)

target_link_libraries(clicom_transport
    PUBLIC
        clicom_common
        ssl
        crypto
        ws2_32
)

clicom_set_warnings(clicom_transport)
