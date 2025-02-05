cmake_minimum_required(VERSION 3.16)

project(eBPF)

add_executable(bootstrap bootstrap.c)

# 設定 C++ 標準
target_compile_features(bootstrap PRIVATE cxx_std_23)
