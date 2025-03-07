#pragma onec

#define MAX_ARG_LEN 256 // max 484

struct event_base
{
    long id;
};

struct command_event
{
    struct event_base base;

    __u64 pid_tgid;
    __u64 ktime;
    int i;
    char argv_i[MAX_ARG_LEN];
};

struct signal_event
{
    struct event_base base;

    pid_t sender_pid;
    pid_t sender_tid;
    pid_t target_pid;
    pid_t target_tid;
    int signal;
    int ret;
};
