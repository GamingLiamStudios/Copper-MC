cmake_minimum_required(VERSION 3.9)
project(main-executable C)

if(NOT MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/.cmake)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Copper-MC)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Copper-MC)
option(BUILD_SHARED_LIBS "" off)

include(find_libraries)

set(THREADS_PREFER_PTHREAD_FLAG on)
find_package(Threads REQUIRED)

if(NOT CMAKE_USE_PTHREADS_INIT)
    message(FATAL_ERROR "Copper-MC requires pthreads")
endif()

find_package(OpenSSL REQUIRED Crypto)

set(SOURCE_FILES
    source/main.c

    source/server/server.c
    
    source/network/socket.c
    source/network/varints.c
    source/network/network_manager.c

    source/network/packets/packet_builder.c
    source/network/packets/packet_reader.c

    source/util/containers/slotmap.c
    source/util/containers/queue.c
    source/util/containers/buffer.c

    source/logger/logger.c
)

add_executable(main-executable ${SOURCE_FILES})

target_compile_features(main-executable PUBLIC c_std_99)
set_target_properties(main-executable PROPERTIES OUTPUT_NAME "Copper-MC")

target_include_directories(main-executable PUBLIC "extern")
target_include_directories(main-executable PRIVATE "source") # to allow paths relative to project root

# TODO: Check if unistring is Windows compatible, or at least MSYS compatible
target_link_libraries(main-executable PRIVATE m unistring Threads::Threads zlib OpenSSL::Crypto curl json-c::json-c)
