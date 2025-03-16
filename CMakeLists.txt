cmake_minimum_required(VERSION 3.28)

project(eBPF)

# 加入 cmake 模組
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

include(ExternalProject)

# 編譯 libbpf 並且安裝到 <INSTALL_DIR> 中
ExternalProject_Add(libbpf
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/libbpf/src
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make
        BUILD_STATIC_ONLY=TRUE
        OBJDIR=<DOWNLOAD_DIR>/libbpf-build
        DESTDIR=<INSTALL_DIR>
        install
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
)

# 指定 libbpf.a 位置和 include 目錄
set(LIBBPF_LIBRARIES ${CMAKE_BINARY_DIR}/libbpf-prefix/usr/lib64/libbpf.a)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/libbpf-prefix/usr/include)

# 編譯 bpftool 的 bootstrap 階段
ExternalProject_Add(bpftool
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/bpftool/src
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make
        HOSTCC=${CMAKE_C_COMPILER}
        BPF_DIR=${CMAKE_SOURCE_DIR}/libbpf/src
        LIBBPF_BOOTSTRAP=${LIBBPF_LIBRARIES}
        LIBBPF_BOOTSTRAP_INCLUDE=${LIBBPF_INCLUDE_DIRS}
        BOOTSTRAP_OUTPUT=<DOWNLOAD_DIR>/bpftool-build/
        bootstrap
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    DEPENDS libbpf
)

# 指定 bpftool 執行檔的位置
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_BINARY_DIR}/bpftool-prefix/src/bpftool-build/bpftool)
set(BPFOBJECT_VMLINUX_H   ${CMAKE_BINARY_DIR}/bpftool-prefix/src/bpftool-build/vmlinux.h)

# 編譯 blazesym
ExternalProject_Add(blazesym
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/blazesym
    CONFIGURE_COMMAND ""
    BUILD_COMMAND cargo build
        --release
        --package blazesym-c
        --target-dir <DOWNLOAD_DIR>/blazesym-build/
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
)

# 指定 blazesym 的 .a 和 include 的位置
add_library(blazesym_c STATIC IMPORTED)
add_dependencies(blazesym_c blazesym)
set_target_properties(blazesym_c PROPERTIES
    IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/blazesym-prefix/src/blazesym-build/release/libblazesym_c.a
    INTERFACE_LINK_LIBRARIES "-lpthread;-lrt;-ldl"
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR}/blazesym/capi/include
)

# 產生 BPF 需要的 vmlinux.h
add_custom_command(
    OUTPUT  ${BPFOBJECT_VMLINUX_H}
    COMMAND ${BPFOBJECT_BPFTOOL_EXE} btf dump file /sys/kernel/btf/vmlinux format c > ${BPFOBJECT_VMLINUX_H}
    DEPENDS bpftool
    COMMENT "Dumping vmlinux.h via bpftool..."
)
add_custom_target(vmlinux_h DEPENDS "${BPFOBJECT_VMLINUX_H}")

find_package(BpfObject REQUIRED)

bpf_object(bootstrap bootstrap.bpf.c)
add_executable(bootstrap bootstrap.c)
add_dependencies(bootstrap_skel vmlinux_h)
target_link_libraries(bootstrap bootstrap_skel)
target_compile_features(bootstrap PRIVATE cxx_std_23)

bpf_object(signal signal.bpf.c)
add_executable(signal signal.cpp)
add_dependencies(signal_skel vmlinux_h)
target_link_libraries(signal signal_skel blazesym_c)
target_compile_features(signal PRIVATE cxx_std_23)
