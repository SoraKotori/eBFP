// ebpf_program.c
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

// 定義 eBPF 映射，用於存儲數據
BPF_PERF_OUTPUT(events);

// 定義 eBPF 探針，用於攔截系統調用
int on_execve(struct pt_regs *ctx, const char __user *filename, const char __user *const __user *argv) {
    char cmd[PATH_MAX] = {};
    bpf_probe_read_user(cmd, sizeof(cmd), filename);
    
    // 將命令名稱發送到用戶空間
    events.perf_submit(ctx, &cmd, sizeof(cmd));
    return 0;
}
