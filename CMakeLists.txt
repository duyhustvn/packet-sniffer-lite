cmake_minimum_required(VERSION 3.16)

project(packet-sniffer-lite
    VERSION 0.1.0
    LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Check if environment variable DEBUG=1 is set to default to Debug build
if(NOT CMAKE_BUILD_TYPE)
  if("$ENV{DEBUG}" STREQUAL "1")
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build" FORCE)
  else()
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build" FORCE)
  endif()
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_definitions(DEBUG)
endif()

add_library(sniffer_parsers
    src/packet_parser.c
    src/packet.c
    src/http_parser.c
    src/tls_sni_parser.c
    src/flow.c
    src/util.c
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
    tests/unity/unity.c
)
target_include_directories(test_parsers
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/unity
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

add_executable(test_flow
    tests/test_flow.c
    tests/unity/unity.c
)
target_include_directories(test_flow
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/unity
)
target_link_libraries(test_flow
    PRIVATE
        sniffer_parsers
)
target_compile_options(test_flow
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

add_test(NAME parsers COMMAND test_parsers)
add_test(NAME flow COMMAND test_flow)

install(TARGETS packet-sniffer-lite RUNTIME DESTINATION bin)
