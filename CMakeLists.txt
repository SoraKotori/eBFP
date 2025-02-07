cmake_minimum_required(VERSION 3.28)

project(eBPF)

# add_executable(bootstrap bootstrap.c)

# 設定 C++ 標準
# target_compile_features(bootstrap PRIVATE cxx_std_23)

include(ExternalProject)

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

ExternalProject_Add(bpftool
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/bpftool/src
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make
        HOSTCC=${CMAKE_C_COMPILER}
        BPF_DIR=${CMAKE_SOURCE_DIR}/libbpf/src
        LIBBPF_BOOTSTRAP=${CMAKE_BINARY_DIR}/libbpf-prefix/usr/lib64/libbpf.a
        LIBBPF_BOOTSTRAP_INCLUDE=${CMAKE_BINARY_DIR}/libbpf-prefix/usr/include
        BOOTSTRAP_OUTPUT=<DOWNLOAD_DIR>/bpftool-build/
        bootstrap
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    DEPENDS libbpf
)
