#pragma onec

#define MAX_ARG_LEN 256 // ebpf stack max 512 bytes
#define MAX_NAME_LEN 64
#define MAX_SYSCALL 8 // 512 divide 64

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

#define EVENT_LIST \
    MAKE_EVENT_ID(sys_enter_execve_event) \
    MAKE_EVENT_ID(sys_exit_execve_event) \
    MAKE_EVENT_ID(sys_enter_kill_event) \
    MAKE_EVENT_ID(sys_exit_kill_event) \
    MAKE_EVENT_ID(sys_enter_read_event) \
    MAKE_EVENT_ID(sys_exit_read_event) \
    MAKE_EVENT_ID(path_event) \
    MAKE_EVENT_ID(vm_area_event) \
    MAKE_EVENT_ID(sched_process_exit_event) \
    MAKE_EVENT_ID(do_coredump_event) \
    MAKE_EVENT_ID(sys_exit_event)

#define EVENT_ID(EVENT_TYPE) EVENT_TYPE##_ID

enum event_ids {
#define MAKE_EVENT_ID(EVENT_TYPE) EVENT_ID(EVENT_TYPE),
    EVENT_LIST
#undef MAKE_EVENT_ID
    EVENT_MAX
};

struct event_base
{
    enum event_ids event_id;
};

#define PID_TGID_UNION \
union                  \
{                      \
    __u64 pid_tgid;    \
    struct             \
    {                  \
        __u32 pid;     \
        __u32 tgid;    \
    };                 \
}

struct sys_enter_execve_event
{
    struct event_base base;

    PID_TGID_UNION;
    __u64 ktime;
    __u32 i;
    __u32 argv_i_size;
    char  argv_i[MAX_ARG_LEN];
};

struct sys_exit_execve_event
{
    struct event_base base;

    PID_TGID_UNION;
    __u64 ktime;
    long ret;
};

struct sys_enter_kill_event
{
    struct event_base base;

    PID_TGID_UNION;
    __u32 target_pid;
    int signal;
};

struct sys_exit_kill_event
{
    struct event_base base;

    PID_TGID_UNION;
    int ret;
};

struct sys_enter_read_event
{
    struct event_base base;

    PID_TGID_UNION;
    __u32 index;
    __u32 size;
    char buf[MAX_ARG_LEN];
};

struct sys_exit_read_event
{
    struct event_base base;

    PID_TGID_UNION;
    int fd;
    int ret;
    __u16 i_mode;
    struct path path;
};

struct path_event
{
    struct event_base base;

    __u32 index;
    struct path path;
};

struct vm_area_event
{
    struct event_base base;

    PID_TGID_UNION;
    __u64 ktime;
    struct vm_area
    {
        unsigned long vm_start;
        unsigned long vm_end;
        unsigned long vm_pgoff;
        unsigned long dentry;
    } area[8];
};

struct sched_process_exit_event
{
    struct event_base base;

    PID_TGID_UNION;
    int exit_code;
};

struct do_coredump_event
{
    struct event_base base;

    PID_TGID_UNION;
    int si_signo;
    int si_code;
    __u32 stack_id;
};

struct sys_exit_event
{
    struct event_base base;

    PID_TGID_UNION;
    long syscall_nr;
    long ret;
    __u32 stack_id;
};

struct self_t
{
    PID_TGID_UNION;
    __u64 dev;
    __u64 ino;
};
