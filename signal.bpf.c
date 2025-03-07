#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <asm/unistd.h>

#include "signal.h"

#define MAX_ARGS 64

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[MAX_ARG_LEN]);
} command_pattern SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, char[MAX_ARG_LEN]);
} commands SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    const char *const *argv = NULL;
    long error = BPF_CORE_READ_INTO(&argv, ctx, args[1]);
    if  (error < 0)
        return 0;

    INIT_EVENT(event, sys_enter_execve_event,
        .pid_tgid = bpf_get_current_pid_tgid(),
        .ktime = bpf_ktime_get_ns()
    );

    int i = 0;

    #pragma unroll
    for (; i < MAX_ARGS; i++)
    {
        const char *argv_i = NULL;

        // 從 user space 讀取 argv[i] 中的字串指標
        error = bpf_core_read_user(&argv_i, sizeof(argv_i), argv + i);
        if (error < 0)
            return 0;

        if (argv_i == NULL)
            break;

        // 讀取 user space 中 argv[i] 的字串內容到 event 中
        error = bpf_core_read_user_str(event.argv_i, sizeof(event.argv_i), argv_i);
        if (error < 0)
            return 0;

        event.i = i;
        
        error = bpf_perf_event_output(ctx,
                                      &events,
                                      BPF_F_CURRENT_CPU,
                                      &event,
                                      offsetof(struct sys_enter_execve_event, argv_i) + error); // length
        if (error < 0)
            return 0;
    }

    event.i = i;

    error = bpf_perf_event_output(ctx,
                                  &events,
                                  BPF_F_CURRENT_CPU,
                                  &event,
                                  offsetof(struct sys_enter_execve_event, i) + sizeof(event.i));
    if (error < 0)
        return 0;
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
    INIT_EVENT(event, sys_exit_execve_event,
        .pid_tgid = bpf_get_current_pid_tgid(),
        .ktime = bpf_ktime_get_ns(),
        .ret = ctx->ret
    );

    long error = bpf_perf_event_output(ctx,
                                       &events,
                                       BPF_F_CURRENT_CPU,
                                       &event,
                                       sizeof(event));
    if (error < 0)
        return 0;

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int tracepoint__syscalls__sys_enter_kill(struct trace_event_raw_sys_enter *ctx)
{
    if (!ctx->args[1]) // signal == 0
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    INIT_EVENT(event, sys_enter_kill_event,
        .sender_pid = pid_tgid >> 32,   // process ID
        .sender_tid = pid_tgid,         // thread ID
        .target_pid = ctx->args[0],
        .signal     = ctx->args[1]
    );
    
    long error = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if  (error < 0)
        return 0;

    return 0;
}

// SEC("raw_tracepoint/sys_enter")
// int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx)
// {
//     __u64 pid_tgid = bpf_get_current_pid_tgid();

//     struct sys_enter_kill_event event =
//     {
//         .sender_pid = pid_tgid >> 32,
//         .sender_tid = pid_tgid
//     };
    
//     unsigned long args[3];
//     if (BPF_CORE_READ_INTO(&args, ctx, args))
//         return 0;

//     switch (ctx->event_id)
//     {
//         case __NR_execve:
//         case __NR_kill:
//             event.target_pid = args[0];
//             event.signal     = args[1];
//             break;
//         case __NR_tkill:
//             event.target_tid = args[0];
//             event.signal     = args[1];
//             break;
//         case __NR_tgkill:
//             event.target_pid = args[0];
//             event.target_tid = args[1];
//             event.signal     = args[2];
//             break;
//     }

//     bpf_perf_event_output(ctx, &signal_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
//     return 0;
// }

SEC("kprobe/__send_signal")
int BPF_KPROBE(kprobe__send_signal, int sig, struct siginfo *info, struct task_struct *task)
{
    pid_t sender_pid = BPF_CORE_READ(info, _sifields._kill._pid);
    uid_t sender_uid = BPF_CORE_READ(info, _sifields._kill._uid);
    pid_t target_pid = BPF_CORE_READ(task, pid);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
