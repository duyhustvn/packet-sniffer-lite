cmake_minimum_required(VERSION 3.16)

project(packet-sniffer-lite
    VERSION 0.1.0
    LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(sniffer_parsers
    src/packet_parser.c
    src/http_parser.c
    src/tls_sni_parser.c
)
target_include_directories(sniffer_parsers
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_compile_options(sniffer_parsers
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

add_executable(packet-sniffer-lite
    src/main.c
)
target_link_libraries(packet-sniffer-lite
    PRIVATE
        sniffer_parsers
)
target_compile_options(packet-sniffer-lite
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

enable_testing()

add_executable(test_parsers
    tests/test_parsers.c
)
target_link_libraries(test_parsers
    PRIVATE
        sniffer_parsers
)
target_compile_options(test_parsers
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

add_test(NAME parsers COMMAND test_parsers)

install(TARGETS packet-sniffer-lite RUNTIME DESTINATION bin)
