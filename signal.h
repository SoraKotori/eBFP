#pragma onec

#define MAX_ARG_LEN 256 // ebpf stack max 512 bytes

#define EVENT_LIST \
    MAKE_EVENT_ID(sys_enter_execve_event) \
    MAKE_EVENT_ID(sys_exit_execve_event) \
    MAKE_EVENT_ID(sys_enter_kill_event) \
    MAKE_EVENT_ID(sys_exit_kill_event) \
    MAKE_EVENT_ID(sched_process_exit_event)

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
    int i;
    char argv_i[MAX_ARG_LEN];
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

struct sched_process_exit_event
{
    struct event_base base;

    PID_TGID_UNION;
    int exit_code;
};
