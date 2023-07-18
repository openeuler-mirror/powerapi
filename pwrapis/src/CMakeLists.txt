cmake_minimum_required (VERSION 3.16)
project (pwrapis C)
set ( CMAKE_INCLUDE_CURRENT_DIR ON)
set ( CMAKE_INSTALL_PREFIX "/usr")
# Add head file directory
include_directories ("${PROJECT_SOURCE_DIR}/../inc")
include_directories ("${PROJECT_SOURCE_DIR}/../../common/inc")

# Load source file
aux_source_directory(${PROJECT_SOURCE_DIR}/../../common/src COMMON_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR} PWRAPIS_SRC_DIR)
set(PWRAPIS_SRC ${COMMON_SRC} ${PWRAPIS_SRC_DIR})

# Set compiling policy
set (PG_NAME ${PROJECT_NAME})
add_executable (${PG_NAME} ${PWRAPIS_SRC})
target_link_libraries(${PG_NAME} -lpthread)
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set installaltion path
#set ( CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}")
set ( CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Install path prefix" FORCE)
#install (TARGETS ${PG_NAME} DESTINATION bin)
install (TARGETS ${PG_NAME} DESTINATION sbin)

# Install default config files
install (FILES "${PROJECT_SOURCE_DIR}/../conf/pwrapis_config.ini"
    DESTINATION /etc/sysconfig/pwrapis PERMISSIONS OWNER_READ OWNER_WRITE)
install (FILES "${PROJECT_SOURCE_DIR}/../pwrapis.service" DESTINATION /usr/lib/systemd/system)

# release complile mode
#set(CMAKE_BUILD_TYPE "Release")
#set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

# debug complile mode
set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")

