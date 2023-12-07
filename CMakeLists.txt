cmake_minimum_required (VERSION 3.16)
project (powerapi_entrance C)
set(CMAKE_VERBOSE_MAKEFILE on)

if(DEFINED RELEASE_MODE)
    add_definitions(-DRELEASE_MODE=${RELEASE_MODE})
endif()

add_subdirectory(pwrapic/src)
add_subdirectory(pwrapis/src)

if(NOT DEFINED RELEASE_MODE)
    add_subdirectory(pwrapic/gtest)
    add_subdirectory(pwrapic/test)
endif(NOT DEFINED RELEASE_MODE)

