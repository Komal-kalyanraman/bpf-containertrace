cmake_minimum_required(VERSION 3.20)
project(bpf-containertrace C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# -------------------------------------------------------------------------
# Locate required tools
# -------------------------------------------------------------------------
find_program(CLANG    clang-18 REQUIRED DOC "Clang for BPF bytecode compilation")
find_program(BPFTOOL  bpftool  REQUIRED DOC "bpftool for skeleton generation")
find_program(LLVM_STRIP llvm-strip-18 NAMES llvm-strip-18 llvm-strip
             DOC "llvm-strip to strip debug from BPF object")

# Detect host architecture for the BPF -D__TARGET_ARCH_* flag
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    set(BPF_ARCH_FLAG "-D__TARGET_ARCH_x86")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(BPF_ARCH_FLAG "-D__TARGET_ARCH_arm64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    set(BPF_ARCH_FLAG "-D__TARGET_ARCH_arm")
else()
    message(WARNING "Unknown arch ${CMAKE_SYSTEM_PROCESSOR}, defaulting to x86")
    set(BPF_ARCH_FLAG "-D__TARGET_ARCH_x86")
endif()

# -------------------------------------------------------------------------
# Directories
# -------------------------------------------------------------------------
set(SRC_DIR     ${CMAKE_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(GEN_DIR     ${CMAKE_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GEN_DIR})

# -------------------------------------------------------------------------
# Step 1: Generate vmlinux.h from the running kernel's BTF
# -------------------------------------------------------------------------
set(VMLINUX_H ${GEN_DIR}/vmlinux.h)

add_custom_command(
    OUTPUT  ${VMLINUX_H}
    COMMAND ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}
    COMMENT "Generating vmlinux.h from /sys/kernel/btf/vmlinux"
    VERBATIM
)
add_custom_target(gen_vmlinux DEPENDS ${VMLINUX_H})

# -------------------------------------------------------------------------
# Step 2: Compile the BPF C program to a BPF ELF object
# -------------------------------------------------------------------------
set(BPF_SRC ${SRC_DIR}/bpf/containertrace.bpf.c)
set(BPF_OBJ ${GEN_DIR}/containertrace.bpf.o)

add_custom_command(
    OUTPUT  ${BPF_OBJ}
    COMMAND ${CLANG}
                -g -O2
                -target bpf
                ${BPF_ARCH_FLAG}
                -D__BPF_PROGRAM__
                -I${INCLUDE_DIR}
                -I${GEN_DIR}
                -I/usr/include
                -I/usr/include/bpf
                -c ${BPF_SRC}
                -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC} gen_vmlinux
            ${INCLUDE_DIR}/containertrace_event.h
    COMMENT "Compiling BPF program: containertrace.bpf.c"
    VERBATIM
)
add_custom_target(bpf_obj DEPENDS ${BPF_OBJ})

# -------------------------------------------------------------------------
# Step 3: Generate the libbpf skeleton header
# -------------------------------------------------------------------------
set(SKEL_H ${GEN_DIR}/containertrace.skel.h)

add_custom_command(
    OUTPUT  ${SKEL_H}
    COMMAND ${BPFTOOL} gen skeleton ${BPF_OBJ} name containertrace > ${SKEL_H}
    DEPENDS bpf_obj
    COMMENT "Generating BPF skeleton: containertrace.skel.h"
    VERBATIM
)
add_custom_target(bpf_skel DEPENDS ${SKEL_H})

# -------------------------------------------------------------------------
# Step 4: User-space daemon
# -------------------------------------------------------------------------
add_executable(bpf-containertrace
    ${SRC_DIR}/main.c
    ${SRC_DIR}/cgroup_resolver.c
)

add_dependencies(bpf-containertrace bpf_skel)

target_include_directories(bpf-containertrace PRIVATE
    ${INCLUDE_DIR}
    ${GEN_DIR}          # containertrace.skel.h + vmlinux.h
    /usr/include/bpf    # libbpf public headers
)

target_compile_options(bpf-containertrace PRIVATE
    -Wall -Wextra -Wno-unused-parameter
)

target_link_libraries(bpf-containertrace PRIVATE
    bpf     # libbpf
    elf     # libelf (libbpf dependency)
    z       # zlib   (libbpf dependency)
)

# -------------------------------------------------------------------------
# Install layout
# -------------------------------------------------------------------------
install(TARGETS bpf-containertrace RUNTIME DESTINATION bin)

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
message(STATUS "Build configuration:")
message(STATUS "  Clang:        ${CLANG}")
message(STATUS "  bpftool:      ${BPFTOOL}")
message(STATUS "  BPF arch:     ${BPF_ARCH_FLAG}")
message(STATUS "  Build type:   ${CMAKE_BUILD_TYPE}")
