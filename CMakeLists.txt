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
        OBJDIR=<DOWNLOAD_DIR>/libbpf-build
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
)

ExternalProject_Add(bpftool
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/bpftool/src
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make bootstrap
        OUTPUT=<DOWNLOAD_DIR>/bpftool-build
        HOSTCC=clang
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
)
