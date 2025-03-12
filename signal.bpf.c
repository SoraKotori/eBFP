#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <asm/unistd.h>

#include "signal.h"

#define MAX_ARGS 64
#define MAX_PID_TGIDS 8192

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[MAX_ARG_LEN]);
} command_pattern SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PID_TGIDS);
    __type(key, __u64);
    __type(value, int);
} execve_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PID_TGIDS);
    __type(key, __u64);
    __type(value, int);
} kill_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_PID_TGIDS);
    __type(key, u32);
    __type(value, u64[PERF_MAX_STACK_DEPTH]);
} stack_trace SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

#define INIT_EVENT(name, EVENT_TYPE, ...) \
struct EVENT_TYPE name =                  \
{                                         \
    .base =                               \
    {                                     \
        .event_id = EVENT_ID(EVENT_TYPE)  \
    },                                    \
    __VA_ARGS__                           \
}

// 將數值轉換為字串，用於輸出檔案與行號
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define PRINT_ERROR(error) \
    bpf_printk("%s: error: %d: %s", __FILE__ ":" STR(__LINE__), error, __func__)

#define CHECK_ERROR(expr)    \
({                           \
    long __err = (expr);     \
    if  (__err < 0)          \
    {                        \
        PRINT_ERROR(__err);  \
        return 0;            \
    }                        \
    __err;                   \
})

#define PRINT_NULL() \
    bpf_printk("%s: null pointer: %s", __FILE__ ":" STR(__LINE__), __func__)

#define CHECK_PTR(expr)          \
({                               \
    typeof(expr) __ptr = (expr); \
    if (!__ptr)                  \
        PRINT_NULL();            \
    __ptr;                       \
})

__always_inline
int pattern_strcmp(const char *const pattern, const char *const arg)
{
    if (pattern[0] == '\0')
        return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
    #pragma unroll
#endif
    for (int i = 0; i < MAX_ARG_LEN; i++)
    {
        unsigned char c1 = arg[i];
        unsigned char c2 = pattern[i];
        if (c1 != c2)
            return c1 - c2;

        if (c1 == '\0')
            break;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    INIT_EVENT(event, sys_enter_execve_event,
        .pid_tgid = bpf_get_current_pid_tgid(),
        .ktime    = bpf_ktime_get_ns()
    );

    // 從 map 中取得欲比對的 pattern
    __u32 key = 0;
    char* pattern = CHECK_PTR(bpf_map_lookup_elem(&command_pattern, &key));
    if  (!pattern)
        return 0;

    // 從 tracepoint context 中取得 argv 指標，並取得 argv[0]
    const char *const *argv = NULL;
    const char *argv_i = NULL;
    CHECK_ERROR(BPF_CORE_READ_INTO(&argv, ctx, args[1]));
    if (argv) // 若 argv 存在，再嘗試讀取 argv[0]
        CHECK_ERROR(bpf_core_read_user(&argv_i, sizeof(argv_i), argv));

    // 處理「argv 或 argv_i 不存在」的情況：
    // - 如果 pattern 不是空字串，就直接 return 0 (表示不符合條件)；
    // - 如果 pattern 是空字串，則視為匹配，執行輸出流程。
    if (!argv_i)
    {
        if (pattern[0])
            return 0;
        else
            goto output;
    }

    // 讀取 argv[0] 字串到 event.argv_i
    long length = CHECK_ERROR(
        bpf_core_read_user_str(event.argv_i, sizeof(event.argv_i), argv_i));

    // 如果 argv[0] 與 pattern 比對不符，則直接 return
    if (pattern_strcmp(pattern, event.argv_i))
        return 0;

    // 輸出第一次事件
    CHECK_ERROR(bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, &event,
        offsetof(struct sys_enter_execve_event, argv_i) + length));

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
    #pragma unroll
#endif
    // 逐一讀取參數，最多讀到 MAX_ARGS 為止
    for (int i = 1; i < MAX_ARGS; i++)
    {
        // 從 user space 讀取 argv[i] 中的字串指標
        CHECK_ERROR(bpf_core_read_user(&argv_i, sizeof(argv_i), argv + i));
        if (!argv_i)
            break;

        // 將 argv[i] 中的字串讀取到 event.argv_i
        length = CHECK_ERROR(
            bpf_core_read_user_str(event.argv_i, sizeof(event.argv_i), argv_i));
        
        // 將目前參數編號存入 event.i，並輸出事件
        event.i++;
        CHECK_ERROR(bpf_perf_event_output(
            ctx, &events, BPF_F_CURRENT_CPU, &event,
            offsetof(struct sys_enter_execve_event, argv_i) + length));
    }

output:

    // 輸出最後一次事件，只包含參數總數(argc)
    event.i++;
    CHECK_ERROR(bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, &event,
        offsetof(struct sys_enter_execve_event, i) + sizeof(event.i)));

    int value = 0;
    CHECK_ERROR(bpf_map_update_elem(&execve_map, &event.pid_tgid, &value, BPF_ANY));
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
    INIT_EVENT(event, sys_exit_execve_event,
        .pid_tgid = bpf_get_current_pid_tgid(),
    );

    int* value_ptr = bpf_map_lookup_elem(&execve_map, &event.pid_tgid);
    if (!value_ptr)
        return 0;

    CHECK_ERROR(bpf_map_delete_elem(&execve_map, &event.pid_tgid));

    event.ktime = bpf_ktime_get_ns();
    event.ret   = ctx->ret;

    CHECK_ERROR(bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event)));

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int tracepoint__syscalls__sys_enter_kill(struct trace_event_raw_sys_enter *ctx)
{
    INIT_EVENT(event, sys_enter_kill_event,
        .pid_tgid   = bpf_get_current_pid_tgid(),
        .target_pid = ctx->args[0],
        .signal     = ctx->args[1]
    );

    // 檢查 signal 若為 0 則不輸出 event
    if (event.signal == 0)
        return 0;

    // 更新 singal 作為 sys_exit_kill 的判斷條件
    CHECK_ERROR(bpf_map_update_elem(&kill_map, &event.pid_tgid, &event.signal, BPF_ANY));
    
    CHECK_ERROR(bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event)));

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_kill")
int tracepoint__syscalls__sys_exit_kill(struct trace_event_raw_sys_exit *ctx)
{
    INIT_EVENT(event, sys_exit_kill_event,
        .pid_tgid = bpf_get_current_pid_tgid(),
        .ret      = ctx->ret
    );

    int* signal_ptr = bpf_map_lookup_elem(&kill_map, &event.pid_tgid);
    if (!signal_ptr)
        return 0;

    CHECK_ERROR(bpf_map_delete_elem(&kill_map, &event.pid_tgid));
    
    CHECK_ERROR(bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event)));

    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    INIT_EVENT(event, sched_process_exit_event,
        .pid_tgid = bpf_get_current_pid_tgid()
    );

    struct task_struct *task = (struct task_struct *)CHECK_PTR(bpf_get_current_task());

    CHECK_ERROR(BPF_CORE_READ_INTO(&event.exit_code, task, exit_code));

    CHECK_ERROR(bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event)));

    return 0;
}

SEC("kprobe/do_coredump")
int BPF_KPROBE(kprobe__do_coredump, const kernel_siginfo_t *siginfo)
{
    // 取得 user-space stack
    long stack_id = CHECK_ERROR(bpf_get_stackid(ctx, &stack_trace, BPF_F_USER_STACK));

    INIT_EVENT(event, do_coredump_event,
        .pid_tgid = bpf_get_current_pid_tgid(),
        .stack_id = stack_id
    );

    CHECK_ERROR(BPF_CORE_READ_INTO(&event.si_signo, siginfo, si_signo));
    CHECK_ERROR(BPF_CORE_READ_INTO(&event.si_code,  siginfo, si_code));

    CHECK_ERROR(bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event)));

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

// SEC("kprobe/__send_signal")
// int BPF_KPROBE(kprobe__send_signal, int sig, struct siginfo *info, struct task_struct *task)
// {
//     pid_t sender_pid = BPF_CORE_READ(info, _sifields._kill._pid);
//     uid_t sender_uid = BPF_CORE_READ(info, _sifields._kill._uid);
//     pid_t target_pid = BPF_CORE_READ(task, pid);

//     return 0;
// }

char LICENSE[] SEC("license") = "Dual BSD/GPL";
