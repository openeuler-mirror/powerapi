cmake_minimum_required (VERSION 3.16)
project (pwrapic_demo C)
set ( CMAKE_INCLUDE_CURRENT_DIR ON)

# Add head file directory
include_directories ("${PROJECT_SOURCE_DIR}/../inc")
include_directories ("${PROJECT_SOURCE_DIR}/../../common/inc")

# Add dependent lib directory
link_directories( ${PROJECT_SOURCE_DIR}/../../build/pwrapic/src )

# Set compile policy
set (PG_NAME ${PROJECT_NAME})
add_executable (${PG_NAME} procapitest.c demo_main.c)
target_link_libraries(${PG_NAME} -lpwrapi -lpthread)
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set installation path
#set ( CMAKE_INSTALL_PREFIX "/usr/local")
#install (TARGETS ${PG_NAME} DESTINATION lib)

# Release compile mode
#set(CMAKE_BUILD_TYPE "Release")
#set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

# Debug compile mode
set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")

