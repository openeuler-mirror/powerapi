cmake_minimum_required (VERSION 3.16)
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

if(BUILD_LLT)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
endif(BUILD_LLT)

# set installation path
set ( CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Install path prefix" FORCE)
#install (TARGETS ${PG_NAME} DESTINATION sbin)
install (TARGETS ${PG_NAME} DESTINATION lib64)

# Install head files
install (FILES "${PROJECT_SOURCE_DIR}/../inc/powerapi.h" DESTINATION /usr/include/pwrapic)
install (FILES "${PROJECT_SOURCE_DIR}/../../common/inc/pwrdata.h" DESTINATION /usr/include/pwrapic)
install (FILES "${PROJECT_SOURCE_DIR}/../../common/inc/pwrerr.h"  DESTINATION /usr/include/pwrapic)

# Release compile mode
# set(CMAKE_BUILD_TYPE "Release")
# set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

# Debug compile mode
set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g -ggdb -Wall -Wextra -Werror")
