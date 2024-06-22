cmake_minimum_required (VERSION 3.16)
project (powerapi_entrance C)
set(CMAKE_VERBOSE_MAKEFILE on)

if(DEFINED RELEASE_MODE)
    add_definitions(-DRELEASE_MODE=${RELEASE_MODE})
endif()

option(ENABLE_ASAN "Enable Address Sanitizer" OFF)

if(ENABLE_ASAN)
    message(STATUS "AddressSanitizer enabled")
    # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer -fsanitize=undefined")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=address")
endif()

add_subdirectory(pwrapic/src)
add_subdirectory(pwrapis/src)

if(NOT DEFINED RELEASE_MODE)
    add_subdirectory(pwrapic/gtest)
    add_subdirectory(pwrapic/test)
endif(NOT DEFINED RELEASE_MODE)

