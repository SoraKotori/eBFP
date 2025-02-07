
# WSL 需要重新編譯 bpftool
https://github.com/microsoft/WSL/issues/10069#issuecomment-1594928594

# libbpf
https://github.com/libbpf/libbpf

cd libbpf/src
make HOSTCC=clang
make install

# bpftool
https://github.com/libbpf/bpftool

cd ../../bpftool/src
make HOSTCC=clang
make install

# eBPF 專案範例
https://github.com/libbpf/libbpf-bootstrap

# 生成 vmlinux.h
cd ../..
bpftool/src/bpftool -V
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 生成 bootstrap.bpf.o
clang -g \
         -target bpf \
         -c bootstrap.bpf.c -o bootstrap.bpf.o
/usr/lib/llvm-19/bin/llvm-strip -g bootstrap.bpf.o

bpftool gen skeleton bootstrap.bpf.o > bootstrap.skel.h

# 生成 bootstrap
clang -g \
    bootstrap.c -o bootstrap         \
    -lbpf -lelf -lz                  # 連結 libbpf, libelf, libz


cd libbpf/src && make install
cd ../../bpftool/src && make install

# 加入 libbpf.so.1 到環境變數
export LD_LIBRARY_PATH=/usr/lib64

cd ../.. && ./bootstrap