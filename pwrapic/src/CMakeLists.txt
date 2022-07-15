cmake_minimum_required (VERSION 3.19)
project (pwrapi C)
set ( CMAKE_INCLUDE_CURRENT_DIR ON)

# Add head directory
include_directories ("${PROJECT_SOURCE_DIR}/../inc")
include_directories ("${PROJECT_SOURCE_DIR}/../../common/inc")

# Load source file
aux_source_directory(${PROJECT_SOURCE_DIR}/../../common/src COMMON_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR} PWRAPIC_SRC_DIR)
set(PWRAPIC_SRC ${COMMON_SRC} ${PWRAPIC_SRC_DIR})

# Set compile policy
set (PG_NAME ${PROJECT_NAME})
add_library(${PG_NAME} SHARED ${PWRAPIC_SRC})
set_target_properties(${PG_NAME} PROPERTIES LINKER_LANGUAGE C)
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

# set installation path
set ( CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Install path prefix" FORCE)
#install (TARGETS ${PG_NAME} DESTINATION sbin)
install (TARGETS ${PG_NAME} DESTINATION lib)

# Release compile mode
#set(CMAKE_BUILD_TYPE "Release")
#set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

# Debug compile mode
set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")

