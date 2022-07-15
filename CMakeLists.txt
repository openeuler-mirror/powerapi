cmake_minimum_required (VERSION 3.19)
project (powerapi_entrance C)
set(CMAKE_VERBOSE_MAKEFILE on)

add_subdirectory(pwrapic/src)
add_subdirectory(pwrapic/test)
add_subdirectory(pwrapis/src)
