include(FetchContent)

# Include zlib-ng
set(ZLIB_ENABLE_TESTS OFF)
set(WITH_NATIVE_INSTRUCTIONS ON)

FetchContent_Declare(
        zlib
        GIT_REPOSITORY https://github.com/zlib-ng/zlib-ng
        GIT_TAG        2.0.6
)

FetchContent_MakeAvailable(zlib)

find_package(CURL)
if(NOT CURL_FOUND)
    FetchContent_Declare(
            curl
            GIT_REPOSITORY https://github.com/curl/curl
            GIT_TAG        curl-7_80_0
    )
    FetchContent_MakeAvailable(curl)
endif()

find_package(json-c CONFIG)
if(NOT json-c_FOUND)
    FetchContent_Declare(
            json-c
            GIT_REPOSITORY https://github.com/json-c/json-c
            GIT_TAG        json-c-0.15
    )
    FetchContent_MakeAvailable(json-c)
endif()
