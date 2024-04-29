#!/bin/sh

find . -name "cmake_install.cmake" |xargs rm -rf
find . -name "CMakeCache.txt" |xargs rm -rf
find . -name "compile_commands.json" |xargs rm -rf
find . -name "Makefile" |xargs rm -rf
find . -name "CMakeFiles" |xargs rm -rf
find . -name "install_manifest.txt" |xargs rm -rf

rm -rf ./pwrapis/build
rm -rf ./pwrapic/build
rm -rf build
rm -rf release