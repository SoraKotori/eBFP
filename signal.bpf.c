#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <asm/unistd.h>

#include "signal.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

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
