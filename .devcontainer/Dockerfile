FROM ubuntu:25.04 AS base

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive && \
    apt-get -y install --no-install-recommends \
    cmake ninja-build

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive && \
    apt-get -y install --no-install-recommends \
    clang-19 llvm-19

FROM base AS development

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive && \
    apt-get -y install --no-install-recommends \
    gdb

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive && \
    apt-get -y install --no-install-recommends \
    git \
    ca-certificates # https

# RUN apt-get update && export DEBIAN_FRONTEND=noninteractive && \
#     apt-get -y install --no-install-recommends \
#     curl
