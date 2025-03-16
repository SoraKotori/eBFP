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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PID_TGIDS);
    __type(key, __u64);
    __type(value, int);
} execve_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PID_TGIDS);
    __type(key, __u64);
    __type(value, int);
} kill_map SEC(".maps");

struct read_argument
{
    int fd;
    void* buf;
    size_t count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PID_TGIDS);
    __type(key, __u64);
    __type(value, struct read_argument);
} read_map SEC(".maps");

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

#define PRINT_EVENT_SIZE_ERR(event_size, max_size) \
    bpf_printk(__FILE__ ":" STR(__LINE__) " event_size overflow: %d > %d\n", event_size, max_size)

__always_inline
int pattern_strcmp(const char *const pattern, const char *const arg)
{
    // 如果 pattern 為空字串，則視為匹配
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

    _Static_assert(sizeof(event.argv_i), "argv_i must have non-zero size for bpf_core_read_user_str()");

    // 讀取 argv[0] 字串到 event.argv_i
    long length = CHECK_ERROR(
        bpf_core_read_user_str(event.argv_i, sizeof(event.argv_i), argv_i));

    // 如果 argv[0] 與 pattern 比對不符，則直接 return
    if (pattern_strcmp(pattern, event.argv_i))
        return 0;

    // argv_i 必須是 8-byte 對齊，因為 perf_event_output 傳輸的資料大小會自動補齊為 8 的倍數。
    // user space 是透過 buffer size 是否超過 argv_i 的 offset 來判斷是否有資料寫入 argv_i，
    // 所以這個 offset 本身必須剛好對齊，否則會造成判斷錯誤或資料錯位。
    _Static_assert(offsetof(struct sys_enter_execve_event, argv_i) % 8 == 0,
        "argv_i must be 8-byte aligned for perf_event_output()");

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
        .ret      = ctx->ret
    );

    int* execve_ptr = bpf_map_lookup_elem(&execve_map, &event.pid_tgid);
    if (!execve_ptr)
        return 0;

    if (event.ret < 0)
        CHECK_ERROR(bpf_map_delete_elem(&execve_map, &event.pid_tgid));

    event.ktime = bpf_ktime_get_ns();

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

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    int* execve_ptr = bpf_map_lookup_elem(&execve_map, &pid_tgid);
    if (!execve_ptr)
        return 0;

    struct read_argument argument =
    {
        .fd    = ctx->args[0],
        .buf   = (void*)ctx->args[1],
        .count = ctx->args[2]
    };

    CHECK_ERROR(bpf_map_update_elem(&read_map, &pid_tgid, &argument, BPF_ANY));
    
    return 0;
}

union sys_read_event
{
    struct sys_enter_read_event enter;
    struct sys_exit_read_event exit;
};

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint__syscalls__sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    union sys_read_event event;

    // 初始化並填入 sys_exit_read_event 結構
    event.exit.base.event_id = EVENT_ID(sys_exit_read_event);
    event.exit.pid_tgid      = bpf_get_current_pid_tgid();
    event.exit.ret           = ctx->ret;

    // 透過 pid_tgid 從 read_map 中查找對應的 read_argument 結構，如果不存在則不是要監視的 read 事件
    struct read_argument* read_ptr = bpf_map_lookup_elem(&read_map, &event.exit.pid_tgid);
    if (!read_ptr)
        return 0;

    struct read_argument read_argument = *read_ptr;

    // 釋放掉對應的 read_argument
    CHECK_ERROR(bpf_map_delete_elem(&read_map, &event.exit.pid_tgid));

    // 編譯期檢查 event 是否為 8-byte 對齊（perf_event_output 需要對齊）
    // _Static_assert(sizeof(event.exit) % 8 == 0, "event must be 8-byte aligned");

    // 如果要蒐集錯誤時的 stack trace，可在這裡啟用
    // if (event.exit.ret < 0)
    //     event.exit.stack_id = CHECK_ERROR(bpf_get_stackid(ctx, &stack_trace, BPF_F_USER_STACK));

    // 將 sys_exit_read_event 傳送到 user space
    CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &event.exit, sizeof(event.exit)));

    if (event.exit.ret <= 0)
        return 0;

    // 若 ret 為正數，代表有讀取到資料，則轉型成 unsigned 來通過驗證器，避免為負數
    __u32 ret = (__u32)event.exit.ret;

    // ------------------------------------------------------------
    // 以下為另一個事件：將 sys_enter_read_event 拆成多個片段回傳
    // 每個片段包含部分讀取到的使用者資料（透過 bpf_probe_read_user）
    // ------------------------------------------------------------

    // 初始化並填入 sys_enter_read_event 結構
    event.enter.base.event_id = EVENT_ID(sys_enter_read_event);
    event.enter.pid_tgid = bpf_get_current_pid_tgid();

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
    #pragma unroll
#endif
    for (__u32 i = 0; i < MAX_ARGS; i++)
    {
        event.enter.index = i * MAX_ARG_LEN;

        // 如果已經讀完所有資料，就提前結束迴圈
        if (ret <= event.enter.index)
            break;

        event.enter.size = ret - event.enter.index;
        if (event.enter.size > MAX_ARG_LEN)
            event.enter.size = MAX_ARG_LEN;

        // 從使用者空間讀取資料進入 event.enter.buf 中
        CHECK_ERROR(bpf_probe_read_user(event.enter.buf, event.enter.size,
                                        read_argument.buf + event.enter.index));

        // 計算實際的事件大小，避免超過 event.enter 結構大小，主要用途通過驗證器
        int event_size = offsetof(struct sys_enter_read_event, buf) + event.enter.size;
        if (event_size > sizeof(event.enter))
        {
            PRINT_EVENT_SIZE_ERR(event_size, sizeof(event.enter));
            break;
        }

        // 將每個片段的 sys_enter_read_event 傳送到 user space
        CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                          &event.enter, event_size));
    }

    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    INIT_EVENT(event, sched_process_exit_event,
        .pid_tgid = bpf_get_current_pid_tgid()
    );

    bpf_map_delete_elem(&execve_map, &event.pid_tgid);
    
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

    // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // struct mm_struct *mm = BPF_CORE_READ(task, mm);
    // struct vm_area_struct *vma = BPF_CORE_READ(mm, mmap);

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
