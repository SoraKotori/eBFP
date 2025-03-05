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

long make_command(char command[MAX_ARG_LEN], const char *const *argv)
{
    command[0] = '\0';

    char *first = command;
    char *last  = command + MAX_ARG_LEN;

    // 固定迴圈次數，確保迴圈可展開
    #pragma unroll
    for (int i = 0; i < 1; i++)
    {
        const char *arg = NULL;

        // 從 user space 安全讀取 argv[i] 中的字串指標
        if (bpf_core_read_user(&arg, sizeof(arg), &argv[i]) < 0)
            break;
        if (arg == NULL)
            break;
        if (first >= last)
            break;

        // 讀取使用者空間中的字串內容到 command 中
        long length = bpf_core_read_user_str(first, last - first, arg);
        if  (length < 0)
            return length;

        // 如果不是第一個參數，在前一個字串後面加上空格
        if (command < first && first < last)
            *(first - 1) = ' ';

        first += length;
    }

    return first - command;
}

bool is_pattern(const char *const command, const char *const pattern)
{
    return pattern[0] == '\0';
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    const char *const *argv = NULL;
    if (BPF_CORE_READ_INTO(&argv, ctx, args[1]))
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t pid  = pid_tgid;          // thread ID
    pid_t tgid = pid_tgid >> 32;    // process ID

    char new_command[MAX_ARG_LEN];
    char* command = bpf_map_lookup_elem(&commands, &pid);

    if (command)
    {
        long read_size = make_command(command, argv);
        if  (read_size < 0)
            return 0;
    }
    else
    {
        long read_size = make_command(new_command, argv);
        if  (read_size < 0)
            return 0;

        if (bpf_map_update_elem(&commands, &pid, new_command, BPF_ANY))
            return 0;
        command = new_command;
    }
    
    u32 key = 0;
    char *const pattern = bpf_map_lookup_elem(&command_pattern, &key);
    if (!pattern || !is_pattern(command, pattern))
        return 0;

    struct event event =
    {
        .id = ctx->id,
        .command =
        {
            .pid = pid,
            .tgid = tgid
        }
    };
    
    if (0 > bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event)))
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
        .id = ctx->id,
        .signal =
        {
            .sender_pid = pid_tgid >> 32,   // process ID
            .sender_tid = pid_tgid,         // thread ID
            .target_pid = ctx->args[0],
            .signal     = ctx->args[1]
        }
    };
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// SEC("raw_tracepoint/sys_enter")
// int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx)
// {
//     __u64 pid_tgid = bpf_get_current_pid_tgid();

//     struct signal_event event =
//     {
//         .sender_pid = pid_tgid >> 32,
//         .sender_tid = pid_tgid
//     };
    
//     unsigned long args[3];
//     if (BPF_CORE_READ_INTO(&args, ctx, args))
//         return 0;

//     switch (ctx->id)
//     {
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
