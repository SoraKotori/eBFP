#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <asm/unistd.h>

#include "signal.h"

#define MAX_ARG_LEN 256 // max 484

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[MAX_ARG_LEN]);
} command_pattern SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, char[MAX_ARG_LEN]);
} commands SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} command_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

long make_command(char *const command, const char *const *argv)
{
    long read_size = 0;
    while (read_size < MAX_ARG_LEN && *argv)
    {
        long length = bpf_core_read_user_str(command + read_size, MAX_ARG_LEN - read_size, *argv++);
        if  (length < 0)
            return length;

        read_size += length;
        command[read_size - 1] = ' ';
    }
    if (read_size)
        command[read_size - 1] = '\0';

    return read_size;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    const char *const *argv = NULL;
    if (BPF_CORE_READ_INTO(&argv, ctx, args[1]))
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t pid  = pid_tgid;          // thread ID
    pid_t tgid = pid_tgid >> 32;    // process ID

    char* const command = bpf_map_lookup_elem(&commands, &pid);

    if (command)
    {
        long read_size = make_command(command, argv);
        if  (read_size < 0)
            return 0;
    }
    else
    {
        char new_command[MAX_ARG_LEN];
        long read_size = make_command(command, argv);
        if  (read_size < 0)
            return 0;

        if (bpf_map_update_elem(&commands, &pid, new_command, BPF_ANY))
            return 0;
    }
    
    struct command_event event =
    {
        .pid = pid,
        .tgid = tgid
    };
    
    if (bpf_perf_event_output(ctx, &command_events, BPF_F_CURRENT_CPU, &event, sizeof(event)))
        return 0;
    
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
        .sender_pid = pid_tgid >> 32,   // process ID
        .sender_tid = pid_tgid,         // thread ID
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
    if (BPF_CORE_READ_INTO(&args, ctx, args))
        return 0;

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
