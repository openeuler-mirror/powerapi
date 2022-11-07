#!/bin/bash

# 要在本地进行gtest用例开发，请先执行该脚本，用于拉取gtest动态库
# 创建软链接和拉取必须的头文件

SCRIPT_DIR=$(cd $(dirname ${BASH_SOURCE[0]}); pwd)

gtest_inc="./include/gtest"
gtest_file="./lib/libgtest.so"

cd $SCRIPT_DIR

echo $SCRIPT_DIR

if [ ! -L "$gtest_file" ]; then
	sudo yum install gtest
	rm -rf lib
	mkdir lib
	ln -s /lib64/`ls /lib64 | grep gtest.so | head -1` ./lib/libgtest.so
	ln -s /lib64/`ls /lib64 | grep gtest_main.so | head -1` ./lib/libgtest_main.so
fi

if [ ! -d "$gtest_inc" ]; then
	rm -rf src_gtest
	mkdir src_gtest
	yumdownloader --source gtest --destdir=./src_gtest
	rpm2cpio ./src_gtest/*.rpm | cpio -div -D ./src_gtest
	tar -zxvf ./src_gtest/release*.tar.gz -C ./src_gtest
	mv ./src_gtest/googletest-release*/googletest/include/gtest ./include
	rm -rf src_gtest
fi
cd -
