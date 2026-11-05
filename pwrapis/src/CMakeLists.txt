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

# ---- P2: eBPF writer-attribution program ----
# Compile bpf_writer.bpf.c once per target CPU architecture. The pt_regs
# layout and the registers holding syscall arguments differ between x86_64
# and arm64, so the load offsets baked into the bytecode differ; the two
# objects are otherwise arch-neutral and the loader (bpfwriter.c) picks the
# right one at runtime via uname().
# This is optional: if clang or the BPF target is unavailable, the loader
# (bpfwriter.c) is still compiled; it simply reports the missing objects at
# runtime and stays inert (best-effort, like the rest of the audit layer).
find_program(BPF_CLANG NAMES clang)
if (BPF_CLANG)
    set(BPF_SRC "${PROJECT_SOURCE_DIR}/../bpf/bpf_writer.bpf.c")
    foreach(BPF_ARCH x86 arm64)
        set(BPF_OBJ_${BPF_ARCH} "${CMAKE_BINARY_DIR}/bpf_writer_${BPF_ARCH}.bpf.o")
        add_custom_command(
            OUTPUT ${BPF_OBJ_${BPF_ARCH}}
            COMMAND ${BPF_CLANG} -target bpf -O2 -g -nostdinc -Werror -Wall
                    -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types
                    -D__TARGET_ARCH_${BPF_ARCH}
                    -c ${BPF_SRC} -o ${BPF_OBJ_${BPF_ARCH}}
            DEPENDS ${BPF_SRC}
            COMMENT "Compiling eBPF writer attribution program (${BPF_ARCH})"
            VERBATIM)
        list(APPEND BPF_OBJS ${BPF_OBJ_${BPF_ARCH}})
        # Install the BPF objects next to the service so the loader can find them.
        install(FILES ${BPF_OBJ_${BPF_ARCH}} DESTINATION /usr/lib/pwrapis)
    endforeach()
    add_custom_target(bpf_writer_object ALL DEPENDS ${BPF_OBJS})
    add_dependencies(${PG_NAME} bpf_writer_object)
endif()

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
# set(CMAKE_BUILD_TYPE "Release")
# set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

# debug complile mode
set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g -ggdb -Wall -Wextra -Werror")
