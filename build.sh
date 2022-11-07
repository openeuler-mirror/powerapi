#!/bin/bash

PWRAPIC="client"
PWRAPIS="server"

mkdir build
cd build
cmake ..

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

mkdir ./release/pwrapi_demo
cp ./build/pwrapic/test/pwrapic_demo  ./release/pwrapi_demo/
cp -r ./release/pwrapic ./release/pwrapi_demo/

mkdir ./release/gtest
cp ./build/pwrapic/gtest/gtest_test  ./release/gtest/


mkdir ./release/pwrapis
cp ./build/pwrapis/src/pwrapis ./release/pwrapis/
cp -r ./pwrapis/conf  ./release/pwrapis/

#make clean
#cd ..
#rm -rf build
