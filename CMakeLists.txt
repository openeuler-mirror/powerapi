cmake_minimum_required (VERSION 3.16)
project (powerapi_entrance C)
set(CMAKE_VERBOSE_MAKEFILE on)

add_subdirectory(pwrapic/src)
add_subdirectory(pwrapic/test)
add_subdirectory(pwrapic/gtest)
add_subdirectory(pwrapis/src)
