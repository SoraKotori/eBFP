#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <asm/unistd.h>

#include "signal.h"

#define MAX_ARG_LEN 4096

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[MAX_ARG_LEN]);
} command_pattern SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    char buffer[MAX_ARG_LEN];

    long read_size = BPF_CORE_READ_STR_INTO(buffer, ctx, args[0]);

    
    char* argv = buffer;
    for (long free_size = MAX_ARG_LEN; free_size && arg_start < arg_end;)
    {
        bpf_core_read_user_str(argv, free_size, arg_start);

    }
    // 讀取 `argv` 陣列 (指標)
    int count = 0;
    for (unsigned long addr = arg_start; addr < arg_end && count < MAX_ARGV_COUNT; addr += sizeof(unsigned long)) {
        bpf_probe_read_user(&argv_ptr[count], sizeof(unsigned long), (void *)addr);
        if (!argv_ptr[count])  // `argv` 陣列以 NULL 結束
            break;
        count++;
    }

    bpf_printk("Argc: %d\n", count);

    // 讀取 `argv[0]` 的內容
    if (count > 0) {
        bpf_probe_read_user(argv, sizeof(argv), (void *)argv_ptr[0]);
        bpf_printk("Command: %s\n", argv);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int tracepoint__syscalls__sys_enter_kill(struct trace_event_raw_sys_enter *ctx)
{
    if (!ctx->args[1])
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct event event =
    {
        .sender_pid = pid_tgid >> 32,
        .sender_tid = pid_tgid,
        .target_pid = ctx->args[0],
        .signal     = ctx->args[1]
    };
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct event event =
    {
        .sender_pid = pid_tgid >> 32,
        .sender_tid = pid_tgid
    };
    
    unsigned long args[3];
    BPF_CORE_READ_INTO(&args, ctx, args);

    // switch (ctx->id)
    // {
    //     case __NR_kill:
    //         event.target_pid = args[0];
    //         event.signal     = args[1];
    //         break;
    //     case __NR_tkill:
    //         event.target_tid = args[0];
    //         event.signal     = args[1];
    //         break;
    //     case __NR_tgkill:
    //         event.target_pid = args[0];
    //         event.target_tid = args[1];
    //         event.signal     = args[2];
    //         break;
    // }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("kprobe/__send_signal")
int BPF_KPROBE(handle_send_signal, int sig, struct siginfo *info, struct task_struct *task)
{
    pid_t sender_pid = BPF_CORE_READ(info, _sifields._kill._pid);
    uid_t sender_uid = BPF_CORE_READ(info, _sifields._kill._uid);
    pid_t target_pid = BPF_CORE_READ(task, pid);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
