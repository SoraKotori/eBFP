#pragma onec

#define MAX_ARG_LEN 256 // ebpf stack max 512 bytes

#define EVENT_LIST \
    MAKE_EVENT_ID(event_base) \
    MAKE_EVENT_ID(sys_enter_execve_event) \
    MAKE_EVENT_ID(sys_exit_execve_event) \
    MAKE_EVENT_ID(sys_enter_kill_event)

enum event_ids {
#define MAKE_EVENT_ID(EVENT_TYPE) EVENT_TYPE##_ID,
    EVENT_LIST
#undef MAKE_EVENT_ID
    EVENT_MAX
};

#define EVENT_ID(EVENT_TYPE) EVENT_TYPE##_ID

struct event_base
{
    enum event_ids event_id;
};

#define INIT_EVENT(name, EVENT_TYPE, ...) \
    struct EVENT_TYPE name = { .base = { .event_id = EVENT_ID(EVENT_TYPE) }, __VA_ARGS__ }

struct sys_enter_execve_event
{
    struct event_base base;

    __u64 pid_tgid;
    __u64 ktime;
    int i;
    char argv_i[MAX_ARG_LEN];
};

struct sys_exit_execve_event
{
    struct event_base base;

    __u64 pid_tgid;
    __u64 ktime;
    long ret;
};

struct sys_enter_kill_event
{
    struct event_base base;

    pid_t sender_pid;
    pid_t sender_tid;
    pid_t target_pid;
    pid_t target_tid;
    int signal;
    int ret;
};
