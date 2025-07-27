#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <asm/unistd.h>

#include "signal.h"

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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct stack_event);
} stack_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct path);
    __type(value, u64);
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
    struct vm_area_struct *vma;
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

int vm_area_tailcall(struct bpf_raw_tracepoint_args *);
int path_tailcall(struct bpf_raw_tracepoint_args *);
int stack_tailcall(struct bpf_raw_tracepoint_args *);

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

#define HANDLE_ERROR(expr, ret) \
({                              \
    long __err = (expr);        \
    if  (__err < 0)             \
    {                           \
        PRINT_ERROR(__err);     \
        return (ret);           \
    }                           \
    __err;                      \
})

#define  CHECK_ERROR(expr) HANDLE_ERROR(expr, 0)
#define RETURN_ERROR(expr) HANDLE_ERROR(expr, __err)

#define PRINT_NULL(expr) \
    bpf_printk(__FILE__ ":" STR(__LINE__) ": null pointer: " #expr ": %s", __func__); \

// 注意：HANDLE_NULL 僅應用於錯誤檢查。
// 對於正常、可接受的退出情形，應直接撰寫：
// if (!__ptr)
//     return 0;
#define HANDLE_NULL(expr, ret)   \
({                               \
    typeof(expr) __ptr = (expr); \
    if (!__ptr)                  \
    {                            \
        PRINT_NULL(expr);        \
        return (ret);            \
    }                            \
    __ptr;                       \
})

#define  CHECK_NULL(expr) HANDLE_NULL(expr, 0)
#define RETURN_NULL(expr) HANDLE_NULL(expr, -2) // ENOENT (No such file or directory)

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
    for (u32 i = 0; i < MAX_PATH_UNROLL; i++)
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

        if ((index -= len) <= MAX_ARG_LEN - MAX_NAME_LEN &&
                      len  <=               MAX_NAME_LEN)
            bpf_probe_read_kernel(dst + index, len, name);
        else
            return -7; // E2BIG (Argument list too long)

        if ((index -= 1) <= MAX_ARG_LEN - MAX_NAME_LEN)
            dst[index] = '/';
        else
            return -7; // E2BIG

        dentry = d_parent;
    }

    return index;
}

static
long output_path(void *ctx, const struct path *path)
{
    const u32 zero = 0;
    struct path_event *event = RETURN_NULL(bpf_map_lookup_elem(&path_buffer, &zero));

    event->base.event_id = EVENT_ID(path_event);
    event->path          = *path;
    event->index         = RETURN_ERROR(read_path(event->name, path));
    event->ktime         = bpf_ktime_get_ns();

    RETURN_ERROR(bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, event,
        offsetof(struct path_event, name) + MAX_ARG_LEN - MAX_NAME_LEN));

    // 如果 bpf_perf_event_output 失敗，則不會更新 ktime
    RETURN_ERROR(bpf_map_update_elem(&path_map, path, &event->ktime, BPF_EXIST));

    return 0;
}

static __always_inline
long try_update_path(void *ctx, const struct path *path)
{
    const u64 ktime = 0;

    long error = bpf_map_update_elem(&path_map, path, &ktime, BPF_NOEXIST);
    if  (error == 0)
        RETURN_ERROR(output_path(ctx, path));
    else if (error != -17) // EEXIST (File exists)
        RETURN_ERROR(error);

    return 0;
}

SEC("raw_tracepoint")
int vm_area_tailcall(struct bpf_raw_tracepoint_args *ctx)
{
    const u32 zero = 0;
    const u64 ktime = 0;

    struct vm_area_event    *event    = CHECK_NULL(bpf_map_lookup_elem(&vm_area_buffer, &zero));
    struct vm_area_argument *argument = CHECK_NULL(bpf_map_lookup_elem(&vm_area_map,    &zero));
    struct path             *paths    = CHECK_NULL(bpf_map_lookup_elem(&path_percpu,    &zero));
    struct file             *file     = NULL;

    u32 i, path_i = argument->path_i;
    struct vm_area_struct *vma = argument->vma;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
    #pragma unroll
#endif
    for (i = 0; i < MAX_AREA; i++)
    {
        barrier();

        if (!vma)
            break;

        struct vm_area *area = &event->area[i];
        bpf_core_read(&area->vm_start, sizeof(area->vm_start), &vma->vm_start);
        bpf_core_read(&area->vm_end,   sizeof(area->vm_end),   &vma->vm_end);
        bpf_core_read(&area->vm_pgoff, sizeof(area->vm_pgoff), &vma->vm_pgoff);
        bpf_core_read(&file,           sizeof(file),           &vma->vm_file);
        bpf_core_read(&vma,            sizeof(vma),            &vma->vm_next);

        if (file)
        {
            bpf_core_read(&area->path, sizeof(area->path), &file->f_path);

            if (bpf_map_update_elem(&path_map, &area->path, &ktime, BPF_NOEXIST) == 0)
            {
                paths[path_i & (MAX_AREA - 1)] = area->path;
                path_i++;
            }
        }
        else
        {
            area->path = (struct path){0};
        }
    }

    event->area_size = i;
    CHECK_ERROR(bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, event,
        offsetof(struct vm_area_event, area[i])));    

    argument->path_i = path_i;
    argument->vma    = vma;

    if (i == MAX_AREA)
        bpf_tail_call_static(ctx, &prog_array_map, TAIL_CALL_ZERO);
    else
        bpf_tail_call_static(ctx, &prog_array_map, TAIL_CALL_ONE);

    bpf_printk("bpf_tail_call_static error");
    return 0;
}

SEC("raw_tracepoint")
int path_tailcall(struct bpf_raw_tracepoint_args *ctx)
{
    const u32 zero = 0;

    struct vm_area_argument *argument = CHECK_NULL(bpf_map_lookup_elem(&vm_area_map, &zero));
    struct path             *paths    = CHECK_NULL(bpf_map_lookup_elem(&path_percpu, &zero));

    u32 path_i = argument->path_i;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
    #pragma unroll
#endif
    for (u32 i = 0; i < 14; i++)
    {
        if (path_i == 0)
            break;

        // struct path* path = bpf_map_lookup_elem(&path_percpu, &path_i);

        path_i = (path_i - 1) & (MAX_AREA - 1);
        CHECK_ERROR(output_path(ctx, &paths[path_i]));
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
int stack_tailcall(struct bpf_raw_tracepoint_args *ctx)
{
    const u32 zero = 0;

    struct stack_event   *stack_event   = CHECK_NULL(bpf_map_lookup_elem(&stack_buffer,   &zero));
    struct vm_area_event *vm_area_event = CHECK_NULL(bpf_map_lookup_elem(&vm_area_buffer, &zero));

    long size = CHECK_ERROR(bpf_get_stack(ctx,
                                          stack_event->addrs,
                                          sizeof(stack_event->addrs),
                                          BPF_F_USER_STACK));

    stack_event->base.event_id = EVENT_ID(stack_event);
    stack_event->pid_tgid      = vm_area_event->pid_tgid;
    stack_event->ktime         = vm_area_event->ktime;
    stack_event->addr_size     = size / sizeof(*stack_event->addrs);

    CHECK_ERROR(bpf_perf_event_output(
        ctx, &events, BPF_F_CURRENT_CPU, stack_event,
        offsetof(struct stack_event, addrs) + size));

    return 0;
}

__always_inline
int pattern_strcmp(const char *const pattern, const char *const arg)
{
    // 如果 pattern 為空字串，則視為匹配
    if (pattern[0] == '\0')
        return 0;

// TODO: 尚未做截斷保護，
//       超過 MAX_ARG_LEN 元素可能導致比較無效
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, u64);
} execve_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    INIT_EVENT(event, sys_enter_execve_event,
        .pid_tgid = bpf_get_current_pid_tgid(),
        .ktime    = bpf_ktime_get_ns()
    );

    // 從 map 中取得欲比對的 pattern
    const u32 zero = 0;
    char *pattern = CHECK_NULL(bpf_map_lookup_elem(&command_pattern, &zero));

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
    // 逐一讀取參數，最多讀到 MAX_ARGV_UNROLL 為止
    for (u32 i = 1; i < MAX_ARGV_UNROLL; i++) 
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

    // 標記此 pid_tgid 在 enter execve 時處理過
    CHECK_ERROR(bpf_map_update_elem(&execve_map, &event.pid_tgid, &event.ktime, BPF_NOEXIST));
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
    INIT_EVENT(event, sys_exit_execve_event,
        .pid_tgid = bpf_get_current_pid_tgid(),
        .ret      = ctx->ret
    );

    // 判斷先前是否在 enter execve 經過處理
    u64 *ktime_ptr = bpf_map_lookup_elem(&execve_map, &event.pid_tgid);
    if (!ktime_ptr)
        return 0;

    event.ktime = *ktime_ptr;

    if (event.ret < 0)
        CHECK_ERROR(bpf_map_delete_elem(&execve_map, &event.pid_tgid));

    CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &event, sizeof(event)));

    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, u64);
} kill_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_kill")
int tracepoint__syscalls__sys_enter_kill(struct trace_event_raw_sys_enter *ctx)
{
    INIT_EVENT(event, sys_enter_kill_event,
        .pid_tgid   = bpf_get_current_pid_tgid(),
        .ktime      = bpf_ktime_get_ns(),
        .target_pid = ctx->args[0],
        .signal     = ctx->args[1]
    );

    // 檢查 signal 若為 0 則不輸出 event
    if (event.signal == 0)
        return 0;

    CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &event, sizeof(event)));

    // 標記此 pid_tgid 在 sys_enter_kill 時處理過
    CHECK_ERROR(bpf_map_update_elem(&kill_map, &event.pid_tgid, &event.ktime, BPF_NOEXIST));

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_kill")
int tracepoint__syscalls__sys_exit_kill(struct trace_event_raw_sys_exit *ctx)
{
    INIT_EVENT(event, sys_exit_kill_event,
        .pid_tgid = bpf_get_current_pid_tgid(),
        .ret      = ctx->ret
    );

    // 判斷先前是否在 sys_enter_kill 經過處理
    u64 *ktime_ptr = bpf_map_lookup_elem(&kill_map, &event.pid_tgid);
    if (!ktime_ptr)
        return 0;

    event.ktime = *ktime_ptr;

    // 即便 key 不存在，也會成功刪除，所以不能用 ENOENT 作為判斷
    CHECK_ERROR(bpf_map_delete_elem(&kill_map, &event.pid_tgid));
    
    CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &event, sizeof(event)));

    return 0;
}

// 在 sys_enter_read 階段，buf 仍未載入任何資料。
// 此時需保存 buf 的位址，待 sys_exit_read 階段後才能取得實際資料。
struct read_argument
{
    int fd;
    void *buf;
    size_t count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct read_argument);
} read_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // 檢查 execve_map 判斷是否要處理 syscall
    u64 *ktime_ptr = bpf_map_lookup_elem(&execve_map, &pid_tgid);
    if (!ktime_ptr)
        return 0;

    struct read_argument argument =
    {
        .fd    =         ctx->args[0],
        .buf   = (void *)ctx->args[1],
        .count =         ctx->args[2]
    };

    // 更新 read_map 作為 sys_exit_read 的判斷條件
    CHECK_ERROR(bpf_map_update_elem(&read_map, &pid_tgid, &argument, BPF_NOEXIST));
    
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} read_content SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint__syscalls__sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    // 使用 union 同時宣告兩個事件結構，共用相同空間避免觸發 eBPF stack 限制
    union
    {
        struct sys_enter_read_event enter;
        struct sys_exit_read_event  exit;
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

    // 若該 path 首次出現，則進行更新
    CHECK_ERROR(try_update_path(ctx, &event.exit.path));

    // ------------------------------------------------------------
    // 處理 sys_exit_read_event 事件:
    // ret、fd、path、inode mode (權限資訊)。
    // ------------------------------------------------------------

    // 初始化並填入 sys_exit_read_event 結構
    event.exit.base.event_id = EVENT_ID(sys_exit_read_event);
    event.exit.pid_tgid      = pid_tgid;
    event.exit.ktime         = bpf_ktime_get_ns();
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

    const u32 zero = 0;
    u32 *context = CHECK_NULL(bpf_map_lookup_elem(&read_content, &zero));
    if (*context == false || event.exit.ret <= 0)
        return 0; // !!! 邏輯錯誤: flag 設為 false 情況下，ret > 0 不會印出，因為沒有發送 enter event

    // 初始化並填入 sys_enter_read_event 結構
    event.enter.base.event_id = EVENT_ID(sys_enter_read_event);

    // 沿用 sys_exit_read_event 的 pid_tgid 和 ktime，並檢查 event 的 offset 一致
    _Static_assert(offsetof(struct sys_enter_read_event, pid_tgid) ==
                   offsetof(struct sys_exit_read_event,  pid_tgid),
                   "layout mismatch: pid_tgid offset differs between enter and exit events");
    _Static_assert(offsetof(struct sys_enter_read_event, ktime) ==
                   offsetof(struct sys_exit_read_event,  ktime),
                   "layout mismatch: ktime offset differs between enter and exit events");

    // 若 ret 為正數，代表有讀取到資料，則轉型成 unsigned 來通過驗證器，避免為負數
    u32 ret = (u32)event.exit.ret;    

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
    #pragma unroll
#endif
    for (u32 i = 0; i < MAX_READ_UNROLL; i++)
    {
        event.enter.index = i * MAX_ARG_LEN;

        // 如果已經讀完所有資料，就提前結束迴圈
        if (ret <= event.enter.index)
            break;

        u32 buf_size = ret - event.enter.index;
        if (buf_size < MAX_ARG_LEN)
            event.enter.size = buf_size & (MAX_ARG_LEN - 1);
        else
            event.enter.size = MAX_ARG_LEN;

        // 從使用者空間讀取資料進入 event.enter.buf 中
        CHECK_ERROR(bpf_probe_read_user(event.enter.buf, event.enter.size,
                                        read_argument.buf + event.enter.index));

        // 計算實際的事件大小，避免超過 event.enter 結構大小，主要用途通過驗證器
        unsigned long event_size = offsetof(struct sys_enter_read_event, buf) + event.enter.size;
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
    struct self_t *self = CHECK_NULL(bpf_map_lookup_elem(&self_map, &zero));

    struct bpf_pidns_info nsdata;
    long error = bpf_get_ns_current_pid_tgid(self->dev, self->ino, &nsdata, sizeof(nsdata));
    if  (error == -22) // EINVAL (invalid argument)
        return 0;
    else
        CHECK_ERROR(error);

    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    INIT_EVENT(event, sys_exit_event,
        .pid        = nsdata.pid,
        .tgid       = nsdata.tgid,
        .syscall_nr = BPF_CORE_READ(regs, orig_ax),
        .ret        = BPF_CORE_READ(regs, ax)
    );

    // 忽略自身的 process
    if (event.pid_tgid == self->pid_tgid)
        return 0;

    // 無效的 syscall
    if (event.syscall_nr == -1)
        return 0;

    u64 *ret_map = CHECK_NULL(bpf_map_lookup_elem(event.ret < 0 ? (void *)&negative_ret_map
                                                                : (void *)&positive_ret_map,
                                                  &zero));

    u64 syscell_idx =      event.syscall_nr / (sizeof(u64) * 8 /* bits */);
    u64 syscell_bit = 1 << event.syscall_nr % (sizeof(u64) * 8 /* bits */);
    
    CHECK_SIZE(syscell_idx, MAX_SYSCALL - 1);

    // 可以考慮再細分成是否要輸出 stack，用 4 個 map 來完成
    // negative_ret_map positive_ret_map negative_stack_map positive_stack_map
    if (ret_map[syscell_idx] & syscell_bit)
    {
        // 需要印出 stack 時，需要提供 ktime 讓 stack_event 能查詢到對應的資訊
        event.ktime = bpf_ktime_get_ns();

        CHECK_ERROR(bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                          &event, sizeof(event)));


        // 以下是 vm_area_event 的處理，沿用 sys_exit_event 的 pid_tgid 和 ktime
        struct vm_area_event *vm_area_event = CHECK_NULL(bpf_map_lookup_elem(&vm_area_buffer, &zero));
        vm_area_event->base.event_id = EVENT_ID(vm_area_event);
        vm_area_event->pid_tgid      = event.pid_tgid;
        vm_area_event->ktime         = event.ktime;

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
    struct self_t *self = CHECK_NULL(bpf_map_lookup_elem(&self_map, &zero));

    struct bpf_pidns_info nsdata;
    long error = bpf_get_ns_current_pid_tgid(self->dev, self->ino, &nsdata, sizeof(nsdata));
    if  (error == -22) // EINVAL (invalid argument)
        return 0;      // dev and inum supplied don't match dev_t and inode number with nsfs of current task
    else
        CHECK_ERROR(error);

    struct mmap_argument argument;
    argument.file  = (void *)PT_REGS_PARM1_CORE(ctx);
    argument.addr  =         PT_REGS_PARM2_CORE(ctx);
    argument.len   =         PT_REGS_PARM3_CORE(ctx);
    argument.prot  =         PT_REGS_PARM4_CORE(ctx);
    argument.flags =         PT_REGS_PARM5_CORE(ctx);

    unsigned long *sp = (unsigned long *)PT_REGS_SP_CORE(ctx);

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

SEC("kretprobe/do_mmap")
int BPF_KPROBE(kretprobe__do_mmap)
{
    const u32 zero = 0;
    struct self_t *self = CHECK_NULL(bpf_map_lookup_elem(&self_map, &zero));

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
        .path  = BPF_CORE_READ(file, f_path),
        .ret   = PT_REGS_RC_CORE(ctx)
    );

    // 釋放掉對應的 mmap_argument
    CHECK_ERROR(bpf_map_delete_elem(&do_mmap_map, &nsdata));

    CHECK_ERROR(try_update_path(ctx, &event.path));

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
