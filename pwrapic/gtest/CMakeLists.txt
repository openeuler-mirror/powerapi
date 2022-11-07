cmake_minimum_required (VERSION 3.19)
project (gtest_test C CXX)
set ( CMAKE_INCLUDE_CURRENT_DIR ON)

execute_process(COMMAND sh ${PROJECT_SOURCE_DIR}/get_gtest.sh)

set(TEST_FILE
    GtestLog.cpp
    GtestBase.cpp
    RegisterOkTest.cpp
)

add_executable(gtest_test
    ${TEST_FILE}
)

# Add head file directory
target_include_directories(gtest_test PRIVATE
    "${PROJECT_SOURCE_DIR}/../inc"
    "${PROJECT_SOURCE_DIR}/../../common/inc"
    "${PROJECT_SOURCE_DIR}/include"
)

target_link_directories(gtest_test PRIVATE
    ${PROJECT_SOURCE_DIR}/../../build/pwrapic/src
    ${PROJECT_SOURCE_DIR}/lib
)

target_link_libraries(gtest_test PRIVATE
    -lpwrapi
    -lgtest
    -lgtest_main
)

set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Debug compile mode
set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")