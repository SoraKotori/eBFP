#pragma onec

struct command_event
{
    pid_t pid;
    pid_t tgid;
};

struct event
{
    pid_t sender_pid;
    pid_t sender_tid;
    pid_t target_pid;
    pid_t target_tid;
    int signal;
    int ret;
};
