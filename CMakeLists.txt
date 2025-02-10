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

find_package(BpfObject REQUIRED)

bpf_object(bootstrap bootstrap.bpf.c)
add_executable(bootstrap bootstrap.c)
target_link_libraries(bootstrap bootstrap_skel)
target_compile_features(bootstrap PRIVATE cxx_std_23)

bpf_object(signal signal.bpf.c)
add_executable(signal signal.cpp)
target_link_libraries(signal signal_skel)
target_compile_features(signal PRIVATE cxx_std_23)
