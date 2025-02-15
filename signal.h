#pragma onec

struct event
{
    pid_t sender_pid;
    pid_t sender_tid;
    pid_t target_pid;
    pid_t target_tid;
    int signal;
    int ret;
};
