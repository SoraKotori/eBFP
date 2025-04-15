#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <asm/unistd.h>

#include "signal.h"

#define MAX_ARGS 32
#define MAX_ENTRIES 1024

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct self_t);
} self_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64[MAX_SYSCALL]);
} negative_ret_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64[MAX_SYSCALL]);
} positive_ret_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[MAX_ARG_LEN]);
} command_pattern SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, int);
} execve_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, int);
} kill_map SEC(".maps");

struct read_argument
{
    int fd;
    void* buf;
    size_t count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} read_content SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct read_argument);
} read_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct stack_event);
} stack_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct path);
    __type(value, u32);
} path_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct path_event);
} path_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct path[MAX_AREA]);
} path_percpu SEC(".maps");

struct vm_area_argument
{
    u32 path_i;
    struct vm_area_struct* vma;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct vm_area_argument);
} vm_area_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct vm_area_event);
} vm_area_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

#define TAIL_CALL_ZERO 0
#define TAIL_CALL_ONE 1
#define TAIL_CALL_TWO 2

int vm_area_tailcall(struct bpf_raw_tracepoint_args*);
int path_tailcall(struct bpf_raw_tracepoint_args*);
int stack_tailcall(struct bpf_raw_tracepoint_args*);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 3);
    __uint(key_size, sizeof(u32));
    __array(values, int (void *));
} prog_array_map SEC(".maps") =
{
    .values =
    {
        [TAIL_CALL_ZERO] = (void *)&vm_area_tailcall,
        [TAIL_CALL_ONE]  = (void *)&path_tailcall,
        [TAIL_CALL_TWO]  = (void *)&stack_tailcall
    },
};

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
    bpf_printk(__FILE__ ":" STR(__LINE__) ": error: %d: %s", error, __func__)

#define CHECK_ERROR(expr)   \
({                          \
    long __err = (expr);    \
    if  (__err < 0)         \
    {                       \
        PRINT_ERROR(__err); \
        return 0;           \
    }                       \
    __err;                  \
})

#define CHECK_PTR(expr)          \
({                               \
    typeof(expr) __ptr = (expr); \
    if (!__ptr)                  \
    {                            \
        bpf_printk(__FILE__ ":" STR(__LINE__) ": null pointer: " #expr ": %s", __func__); \
        return 0;                \
    }                            \
    __ptr;                       \
})

#define CHECK_SIZE(size, expr) \
({                             \
    if (size > expr)           \
    {                          \
        bpf_printk(__FILE__ ":" STR(__LINE__) ": size overflow: " #size " > " #expr); \
        return 0;              \
    }                          \
})

static __always_inline
long read_path(char dst[MAX_ARG_LEN], const struct path *path)
{
    struct dentry *dentry;
    bpf_core_read(&dentry, sizeof(dentry), &path->dentry);

    struct vfsmount *vfsmnt;
    bpf_core_read(&vfsmnt, sizeof(vfsmnt), &path->mnt);

    struct mount *mnt = container_of(vfsmnt, struct mount, mnt);

    struct dentry *mnt_root;
    bpf_core_read(&mnt_root, sizeof(mnt_root), &vfsmnt->mnt_root);

    u32 index = MAX_ARG_LEN - MAX_NAME_LEN;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
    #pragma unroll
#endif
    for (u32 i = 0; i < MAX_ARGS; i++)
    {
        if (dentry == mnt_root)
        {
            struct mount *mnt_parent;
            bpf_core_read(&mnt_parent, sizeof(mnt_parent), &mnt->mnt_parent);
        
            if (mnt == mnt_parent)
                break;

            bpf_core_read(&dentry, sizeof(dentry), &mnt->mnt_mountpoint);
            bpf_core_read(&mnt_root, sizeof(mnt_root), &mnt_parent->mnt.mnt_root);
            mnt = mnt_parent;

            continue;
        }

        struct dentry *d_parent;
        bpf_core_read(&d_parent, sizeof(d_parent), &dentry->d_parent);

        // 在特殊的檔案系統中，如匿名 pipe 並不會經過 mnt_root，而會直接達到自身的 root
        if (dentry == d_parent)
            break;

        const unsigned char *name;
        bpf_core_read(&name, sizeof(name), &dentry->d_name.name);

        u32 len;
        bpf_core_read(&len, sizeof(len), &dentry->d_name.len);

        index -= len + 1;

        if (index > MAX_ARG_LEN - MAX_NAME_LEN)     return -7; // E2BIG (Argument list too long)
        // if (len   >               MAX_NAME_LEN - 1) return -7; // E2BIG (Argument list too long)

        dst[index] = '/';
        bpf_probe_read_kernel(dst + index + 1, len & (MAX_NAME_LEN - 1), name);

        dentry = d_parent;
    }

    return index;
}

static
long path_output(void *ctx, const struct path *path)
{
    const u32 zero = 0;
    struct path_event* event = CHECK_PTR(bpf_map_lookup_elem(&path_buffer, &zero));

    event->base.event_id = EVENT_ID(path_event);
    event->index         = CHECK_ERROR(read_path(event->name, path));
    event->path          = *path;

    CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      event, sizeof(*event)));
    return 0;
}

static __always_inline
long try_update_path(void *ctx, const struct path *path)
{
    const u32 zero = 0;
    long error = bpf_map_update_elem(&path_map, path, &zero, BPF_NOEXIST);
    if  (error == 0)
        CHECK_ERROR(path_output(ctx, path));
    else if (error != -17) // EEXIST (File exists)
        CHECK_ERROR(error);

    return 0;
}

SEC("raw_tracepoint")
int path_tailcall(struct bpf_raw_tracepoint_args *ctx)
{
    const u32 zero = 0;

    struct vm_area_argument *argument = CHECK_PTR(bpf_map_lookup_elem(&vm_area_map, &zero));

    struct path *paths = CHECK_PTR(bpf_map_lookup_elem(&path_percpu, &zero));

    u32 path_i = argument->path_i;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
    #pragma unroll
#endif
    for (u32 i = 0; i < 14; i++)
    {
        if (path_i == 0)
            break;

        path_i = (path_i - 1) & (MAX_AREA - 1);
        CHECK_ERROR(path_output(ctx, &paths[i]));

        // struct path* path = bpf_map_lookup_elem(&path_percpu, &path_i);
    }

    argument->path_i = path_i;

    if (path_i)
        bpf_tail_call_static(ctx, &prog_array_map, TAIL_CALL_ONE);
    else
        bpf_tail_call_static(ctx, &prog_array_map, TAIL_CALL_TWO);

    bpf_printk("bpf_tail_call_static error");
    return 0;
}

SEC("raw_tracepoint")
int stack_tailcall(struct bpf_raw_tracepoint_args* ctx)
{
    const u32 zero = 0;

    struct stack_event   *stack_event   = CHECK_PTR(bpf_map_lookup_elem(&stack_buffer,   &zero));
    struct vm_area_event *vm_area_event = CHECK_PTR(bpf_map_lookup_elem(&vm_area_buffer, &zero));

    long size = CHECK_ERROR(bpf_get_stack(ctx,
                                          stack_event->addrs,
                                          sizeof(stack_event->addrs),
                                          BPF_F_USER_STACK));

    stack_event->base.event_id = EVENT_ID(stack_event);
    stack_event->pid_tgid      = vm_area_event->pid_tgid;
    stack_event->addr_size     = size / sizeof(*stack_event->addrs);

    CHECK_ERROR(bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, stack_event,
        offsetof(struct stack_event, addrs) + size));

    return 0;
}

SEC("raw_tracepoint")
int vm_area_tailcall(struct bpf_raw_tracepoint_args *ctx)
{
    const u32 zero = 0;

    struct vm_area_event* event = CHECK_PTR(bpf_map_lookup_elem(&vm_area_buffer, &zero));

    struct vm_area_argument *argument = CHECK_PTR(bpf_map_lookup_elem(&vm_area_map, &zero));
    
    struct path *paths = CHECK_PTR(bpf_map_lookup_elem(&path_percpu, &zero));

    u32 i, path_i = argument->path_i;
    struct vm_area_struct* vma = argument->vma;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
    #pragma unroll
#endif
    for (i = 0; i < MAX_AREA; i++)
    {
        barrier();

        if (!vma)
            break;

        struct vm_area *area = &event->area[i];

        area->vm_start = BPF_CORE_READ(vma, vm_start);
        area->vm_end   = BPF_CORE_READ(vma, vm_end);
        area->vm_pgoff = BPF_CORE_READ(vma, vm_pgoff);
        area->path     = BPF_CORE_READ(vma, vm_file, f_path);
        vma            = BPF_CORE_READ(vma, vm_next);

        // BPF_CORE_READ_INTO(&area->vm_start, vma, vm_start);
        // BPF_CORE_READ_INTO(&area->vm_end,   vma, vm_end);
        // BPF_CORE_READ_INTO(&area->vm_pgoff, vma, vm_pgoff);
        // BPF_CORE_READ_INTO(&area->path,     vma, vm_file, f_path);
        // BPF_CORE_READ_INTO(&vma,            vma, vm_next);

        // bpf_core_read(&area->vm_start, sizeof(area->vm_start), &vma->vm_start);
        // bpf_core_read(&area->vm_end,   sizeof(area->vm_end),   &vma->vm_end);
        // bpf_core_read(&area->vm_pgoff, sizeof(area->vm_pgoff), &vma->vm_pgoff);
        // bpf_core_read(&area->path,     sizeof(area->path),     &vma->vm_file->f_path);
        // bpf_core_read(&vma,            sizeof(vma),            &vma->vm_next);

        if (area->path.dentry &&
            bpf_map_update_elem(&path_map, &area->path, &zero, BPF_NOEXIST) == 0)
        {
            paths[path_i & (MAX_AREA - 1)] = area->path;
            path_i++;
        }
    }

    event->area_size = i;
    CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      event, offsetof(struct vm_area_event, area[i])));    

    argument->path_i = path_i;
    argument->vma = vma;

    if (i == MAX_AREA)
        bpf_tail_call_static(ctx, &prog_array_map, TAIL_CALL_ZERO);
    else
        bpf_tail_call_static(ctx, &prog_array_map, TAIL_CALL_ONE);

    bpf_printk("bpf_tail_call_static error");
    return 0;
}

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
    const u32 zero = 0;
    char *pattern = CHECK_PTR(bpf_map_lookup_elem(&command_pattern, &zero));

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
    event.argv_i_size = CHECK_ERROR(
        bpf_core_read_user_str(event.argv_i, sizeof(event.argv_i), argv_i));

    // 如果 argv[0] 與 pattern 比對不符，則直接 return
    if (pattern_strcmp(pattern, event.argv_i))
        return 0;

    // 輸出第一次事件
    CHECK_ERROR(bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, &event,
        offsetof(struct sys_enter_execve_event, argv_i) + event.argv_i_size));
    event.i++;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
    #pragma unroll
#endif
    // 逐一讀取參數，最多讀到 MAX_ARGS 為止
    for (u32 i = 1; i < MAX_ARGS; i++) 
    {
        // 從 user space 讀取 argv[i] 中的字串指標
        CHECK_ERROR(bpf_probe_read_user(&argv_i, sizeof(argv_i), argv + event.i));
        if (!argv_i)
            break;

        // 將 argv[i] 中的字串讀取到 event.argv_i
        event.argv_i_size = CHECK_ERROR(
            bpf_core_read_user_str(event.argv_i, sizeof(event.argv_i), argv_i));
        
        // 將目前參數編號存入 event.i，並輸出事件
        CHECK_ERROR(bpf_perf_event_output(
            ctx, &events, BPF_F_CURRENT_CPU, &event,
            offsetof(struct sys_enter_execve_event, argv_i) + event.argv_i_size));
        event.i++;
    }

output:

    // 輸出最後一次事件，只包含參數總數(argc)
    event.argv_i_size = 0;
    CHECK_ERROR(bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, &event,
        offsetof(struct sys_enter_execve_event, argv_i_size) + sizeof(event.argv_i_size)));

    // 標記此 pid_tgid 在 enter execve 時處理過，value 只作為必要參數傳入
    CHECK_ERROR(bpf_map_update_elem(&execve_map, &event.pid_tgid, &zero, BPF_ANY));
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
    INIT_EVENT(event, sys_exit_execve_event,
        .pid_tgid = bpf_get_current_pid_tgid(),
        .ret      = ctx->ret
    );

    // 檢查 execve_map 判斷先前是否在 enter execve 經過處理
    int *execve_ptr = bpf_map_lookup_elem(&execve_map, &event.pid_tgid);
    if (!execve_ptr)
        return 0;

    if (event.ret < 0)
        CHECK_ERROR(bpf_map_delete_elem(&execve_map, &event.pid_tgid));

    event.ktime = bpf_ktime_get_ns();

    CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &event, sizeof(event)));

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

    // 更新 kill_map 作為 sys_exit_kill 的判斷條件
    CHECK_ERROR(bpf_map_update_elem(&kill_map, &event.pid_tgid, &event.signal, BPF_NOEXIST));
    
    CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &event, sizeof(event)));

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_kill")
int tracepoint__syscalls__sys_exit_kill(struct trace_event_raw_sys_exit *ctx)
{
    INIT_EVENT(event, sys_exit_kill_event,
        .pid_tgid = bpf_get_current_pid_tgid(),
        .ret      = ctx->ret
    );

    // 檢查 kill_map 判斷是否要處理 signal
    if (NULL == bpf_map_lookup_elem(&kill_map, &event.pid_tgid))
        return 0;

    // 即便 key 不存在，也會成功刪除，所以不能用 ENOENT 作為判斷
    CHECK_ERROR(bpf_map_delete_elem(&kill_map, &event.pid_tgid));
    
    CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &event, sizeof(event)));

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // 檢查 execve_map 判斷是否要處理 syscall
    int *execve_ptr = bpf_map_lookup_elem(&execve_map, &pid_tgid);
    if (!execve_ptr)
        return 0;

    struct read_argument argument =
    {
        .fd    = ctx->args[0],
        .buf   = (void*)ctx->args[1],
        .count = ctx->args[2]
    };

    // 更新 read_map 作為 sys_exit_read 的判斷條件
    CHECK_ERROR(bpf_map_update_elem(&read_map, &pid_tgid, &argument, BPF_NOEXIST));
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint__syscalls__sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    // 使用 union 同時宣告兩個事件結構，共用相同空間避免觸發 eBPF stack 限制
    union
    {
        struct sys_enter_read_event enter;
        struct sys_exit_read_event exit;
    } event;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    // 透過 pid_tgid 從 read_map 中查找對應的 read_argument 結構，如果不存在則不是要監視的 read 事件
    struct read_argument *read_ptr = bpf_map_lookup_elem(&read_map, &pid_tgid);
    if (!read_ptr)
        return 0;

    // 將讀取到的參數結構複製到本地 stack
    struct read_argument read_argument = *read_ptr;

    // 釋放掉對應的 read_argument
    CHECK_ERROR(bpf_map_delete_elem(&read_map, &pid_tgid));

    // 取得當前 task 結構的指標
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // 透過 BPF_CORE_READ_INTO 取得 task 結構中 files -> fdt -> fd 的指標
    struct file **fd = NULL;
    CHECK_ERROR(BPF_CORE_READ_INTO(&fd, task, files, fdt, fd));

    // 依照檔案描述符的索引，從 fd 陣列中讀取對應的 file 結構指標
    struct file *file = NULL;
    CHECK_ERROR(bpf_probe_read_kernel(&file, sizeof(file), fd + read_argument.fd));

    // 讀取 file 結構中 f_path 欄位
    CHECK_ERROR(BPF_CORE_READ_INTO(&event.exit.path, file, f_path));

    const u32 zero = 0;
    long error = bpf_map_update_elem(&path_map, &event.exit.path, &zero, BPF_NOEXIST);
    if  (error == 0)
        CHECK_ERROR(path_output(ctx, &event.exit.path));
    else if (error != -17) // EEXIST (File exists)
        CHECK_ERROR(error);

    // ------------------------------------------------------------

    // ------------------------------------------------------------

    // 初始化並填入 sys_exit_read_event 結構
    event.exit.base.event_id = EVENT_ID(sys_exit_read_event);
    event.exit.pid_tgid      = pid_tgid;
    event.exit.fd            = read_argument.fd;
    event.exit.ret           = ctx->ret;

    // 讀取 dentry 結構中 inode 的 i_mode 欄位，儲存到 sys_exit_read_event 結構中
    CHECK_ERROR(BPF_CORE_READ_INTO(&event.exit.i_mode, file, f_path.dentry, d_inode, i_mode));

    // 將 sys_exit_read_event 傳送到 user space
    CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &event.exit, sizeof(event.exit)));

    // ------------------------------------------------------------
    // 以下為另一個事件：將 sys_enter_read_event 拆成多個片段回傳
    // 每個片段包含部分讀取到的使用者資料（透過 bpf_probe_read_user）
    // ------------------------------------------------------------

    u32 *context = CHECK_PTR(bpf_map_lookup_elem(&read_content, &zero));
    if (*context == false || event.exit.ret <= 0)
        return 0;

    // 若 ret 為正數，代表有讀取到資料，則轉型成 unsigned 來通過驗證器，避免為負數
    u32 ret = (u32)event.exit.ret;    

    // 初始化並填入 sys_enter_read_event 結構
    event.enter.base.event_id = EVENT_ID(sys_enter_read_event);
    event.enter.pid_tgid = bpf_get_current_pid_tgid();

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
    #pragma unroll
#endif
    for (u32 i = 0; i < MAX_ARGS; i++)
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
        CHECK_SIZE(event_size, sizeof(event.enter));

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
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    CHECK_ERROR(BPF_CORE_READ_INTO(&event.exit_code, task, exit_code));

    CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &event, sizeof(event)));

    return 0;
}

SEC("kprobe/do_coredump")
int BPF_KPROBE(kprobe__do_coredump, const kernel_siginfo_t *siginfo)
{
    INIT_EVENT(event, do_coredump_event,
        .pid_tgid = bpf_get_current_pid_tgid()
    );

    CHECK_ERROR(BPF_CORE_READ_INTO(&event.si_signo, siginfo, si_signo));
    CHECK_ERROR(BPF_CORE_READ_INTO(&event.si_code,  siginfo, si_code));

    CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &event, sizeof(event)));
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tracepoint__sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    const u32 zero = 0;
    struct self_t *self = CHECK_PTR(bpf_map_lookup_elem(&self_map, &zero));

    struct bpf_pidns_info nsdata;
    long error = bpf_get_ns_current_pid_tgid(self->dev, self->ino, &nsdata, sizeof(nsdata));
    if  (error == -22) // EINVAL (invalid argument)
        return 0;
    else
        CHECK_ERROR(error);

    INIT_EVENT(event, sys_exit_event,
        .pid  = nsdata.pid,
        .tgid = nsdata.tgid
    );

    if (event.pid_tgid == self->pid_tgid)
        return 0;

    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    CHECK_ERROR(BPF_CORE_READ_INTO(&event.syscall_nr, regs, orig_ax));
    CHECK_ERROR(BPF_CORE_READ_INTO(&event.ret,        regs, ax));

    u64 *ret_map = CHECK_PTR(bpf_map_lookup_elem(event.ret < 0 ? (void*)&negative_ret_map
                                                               : (void*)&positive_ret_map,
                                                 &zero));

    u64 syscell_idx =      event.syscall_nr / (sizeof(u64) * 8 /* bits */);
    u64 syscell_bit = 1 << event.syscall_nr % (sizeof(u64) * 8 /* bits */);
    
    if (syscell_idx < MAX_SYSCALL &&
        ret_map[syscell_idx] & syscell_bit)
    {
        CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                          &event, sizeof(event)));



        u32 zero = 0;
        struct vm_area_event* vm_area_event = CHECK_PTR(bpf_map_lookup_elem(&vm_area_buffer, &zero));

        vm_area_event->base.event_id = EVENT_ID(vm_area_event);
        vm_area_event->pid_tgid      = event.pid_tgid;
        vm_area_event->ktime         = bpf_ktime_get_ns();

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
        struct vm_area_argument argument =
        {
            .path_i = 0,
            .vma    = BPF_CORE_READ(task, mm, mmap)
        };

        CHECK_ERROR(bpf_map_update_elem(&vm_area_map, &zero, &argument, BPF_ANY));

        bpf_tail_call_static(ctx, &prog_array_map, TAIL_CALL_ZERO);

        bpf_printk("bpf_tail_call_static error");
    }

    return 0;
}

struct mmap_argument
{
    struct file *file;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long pgoff;
    unsigned long *populate;
    struct list_head *uf;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct bpf_pidns_info);
    __type(value, struct mmap_argument);
} do_mmap_map SEC(".maps");

extern __u32 LINUX_KERNEL_VERSION __kconfig;

SEC("kprobe/do_mmap")
int kprobe__do_mmap(struct pt_regs *ctx)
{
    const u32 zero = 0;
    struct self_t *self = CHECK_PTR(bpf_map_lookup_elem(&self_map, &zero));

    struct bpf_pidns_info nsdata;
    long error = bpf_get_ns_current_pid_tgid(self->dev, self->ino, &nsdata, sizeof(nsdata));
    if  (error == -22) // EINVAL (invalid argument)
        return 0;      // dev and inum supplied don't match dev_t and inode number with nsfs of current task
    else
        CHECK_ERROR(error);

    struct mmap_argument argument;
    argument.file  = (void*)PT_REGS_PARM1_CORE(ctx);
    argument.addr  =        PT_REGS_PARM2_CORE(ctx);
    argument.len   =        PT_REGS_PARM3_CORE(ctx);
    argument.prot  =        PT_REGS_PARM4_CORE(ctx);
    argument.flags =        PT_REGS_PARM5_CORE(ctx);

    unsigned long* sp = (unsigned long *)PT_REGS_SP_CORE(ctx);

    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 9, 0))
    {
        CHECK_ERROR(bpf_core_read(&argument.pgoff,    sizeof(*sp), sp + 1));
        CHECK_ERROR(bpf_core_read(&argument.populate, sizeof(*sp), sp + 2));
        CHECK_ERROR(bpf_core_read(&argument.uf,       sizeof(*sp), sp + 3));
    }
    else
    {
        argument.pgoff = PT_REGS_PARM6_CORE(ctx);
        CHECK_ERROR(bpf_core_read(&argument.populate, sizeof(*sp), sp + 1));
        CHECK_ERROR(bpf_core_read(&argument.uf,       sizeof(*sp), sp + 2));
    }

    // 更新 do_mmap_map 傳遞參數給 kretprobe/do_mmap
    CHECK_ERROR(bpf_map_update_elem(&do_mmap_map, &nsdata, &argument, BPF_NOEXIST));

    return 0;
}

#ifndef MAX_ERRNO
#define MAX_ERRNO 4095
#endif

#ifndef IS_ERR_VALUE
#define IS_ERR_VALUE(x) ((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)
#endif

SEC("kretprobe/do_mmap")
int BPF_KPROBE(kretprobe__do_mmap)
{
    unsigned long ret = PT_REGS_RC_CORE(ctx);
    if (IS_ERR_VALUE(ret))
        return 0;

    const u32 zero = 0;
    struct self_t *self = CHECK_PTR(bpf_map_lookup_elem(&self_map, &zero));

    struct bpf_pidns_info nsdata;
    long error = bpf_get_ns_current_pid_tgid(self->dev, self->ino, &nsdata, sizeof(nsdata));
    if  (error == -22) // EINVAL (invalid argument)
        return 0;
    else
        CHECK_ERROR(error);

    // 檢查 do_mmap_map 從中取得參數
    struct mmap_argument *argument = bpf_map_lookup_elem(&do_mmap_map, &nsdata);
    if (!argument)
        return 0;

    struct file *file = argument->file;

    INIT_EVENT(event, do_mmap_event,
        .pid   = nsdata.pid,
        .tgid  = nsdata.tgid,
        .addr  = argument->addr,
        .len   = argument->len,
        .prot  = argument->prot,
        .flags = argument->flags,
        .pgoff = argument->pgoff,
        .uf    = argument->uf,
        .path  = BPF_CORE_READ(file, f_path)
    );

    // 釋放掉對應的 mmap_argument
    CHECK_ERROR(bpf_map_delete_elem(&do_mmap_map, &nsdata));

    error = bpf_map_update_elem(&path_map, &event.path, &zero, BPF_NOEXIST);
    if  (error == 0)
        CHECK_ERROR(path_output(ctx, &event.path));
    else if (error != -17) // EEXIST (File exists)
        CHECK_ERROR(error);

    CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &event, sizeof(event)));

    return 0;
}

// SEC("kprobe/__send_signal")
// int BPF_KPROBE(kprobe__send_signal, int sig, struct siginfo *info, struct task_struct *task)
// {
//     pid_t sender_pid = BPF_CORE_READ(info, _sifields._kill._pid);
//     uid_t sender_uid = BPF_CORE_READ(info, _sifields._kill._uid);
//     pid_t target_pid = BPF_CORE_READ(task, pid);

//     return 0;
// }

char LICENSE[] SEC("license") = "Dual BSD/GPL";
