#!/bin/bash

PWRAPIC="client"
PWRAPIS="server"

mkdir build
cd build
if [[ "$1" == "release" ]];then
    cmake -DRELEASE_MODE="true" ..
elif [[ "$1" == "export" ]]; then  # export compile database
    cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 ..
elif [[ "$1" == "asan" ]]; then
    cmake -DENABLE_ASAN=ON ..
else
    cmake ..
fi

if [ $? -ne 0 ]; then
    exit 1
fi

if [[ "$1" == "$PWRAPIC" ]]
then
    make pwrapi
    make pwrapic_demo
elif [[ "$1" == "$PWRAPIS" ]]
then
    make pwrapis
else
    make all
fi

if [ $? -ne 0 ]; then
    exit 1
fi

cd ..
rm -rf release
mkdir release
mkdir ./release/pwrapic
mkdir ./release/pwrapic/lib
mkdir ./release/pwrapic/inc
cp ./build/pwrapic/src/libpwrapi.so ./release/pwrapic/lib/
cp ./pwrapic/inc/powerapi.h ./release/pwrapic/inc/
cp ./common/inc/pwrdata.h  ./release/pwrapic/inc/
cp ./common/inc/pwrerr.h  ./release/pwrapic/inc/

if [[ "$1" != "release" ]];then
    mkdir ./release/pwrapi_demo
    cp ./build/pwrapic/test/pwrapic_demo  ./release/pwrapi_demo/
    cp -r ./release/pwrapic ./release/pwrapi_demo/

    mkdir ./release/gtest
    cp ./build/pwrapic/gtest/gtest_test  ./release/gtest/
fi

mkdir ./release/pwrapis
cp ./build/pwrapis/src/pwrapis ./release/pwrapis/
cp -r ./pwrapis/conf  ./release/pwrapis/

# Ship the pre-compiled eBPF writer-attribution objects. The bytecode is
# arch-neutral except for the pt_regs register offsets, so one object per
# CPU architecture (x86 / arm64) ships and the loader picks the right one
# via uname(). CMake compiles them when clang is available; otherwise fall
# back to the objects placed in pwrapis/bpf/ so the RPM always carries them.
if ls ./build/bpf_writer_*.bpf.o >/dev/null 2>&1; then
    cp ./build/bpf_writer_*.bpf.o ./release/pwrapis/
elif ls ./pwrapis/bpf/bpf_writer_*.bpf.o >/dev/null 2>&1; then
    cp ./pwrapis/bpf/bpf_writer_*.bpf.o ./release/pwrapis/
fi

#make clean
#cd ..
#rm -rf build
exit 0
