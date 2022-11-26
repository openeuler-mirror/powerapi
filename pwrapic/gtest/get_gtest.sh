#!/bin/bash

# 要在本地进行gtest用例开发，请先执行该脚本，用于拉取gtest动态库
# 创建软链接和拉取必须的头文件
if [ ! -L "/lib64/libgtest.so" ]; then
	sudo yum install gtest-devel
fi