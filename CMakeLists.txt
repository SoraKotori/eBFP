cmake_minimum_required(VERSION 3.16)

project(eBPF_test)

add_executable(eBPF bootstrap.c)

# 設定 C++ 標準
target_compile_features(eBPF PRIVATE cxx_std_23)
