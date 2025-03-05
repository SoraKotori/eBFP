#pragma onec

#define MAX_ARG_LEN 256 // max 484

struct event
{
    long id;

    union
    {
        struct
        {
            pid_t pid;
            pid_t tgid;
        } command;

        struct
        {
            pid_t sender_pid;
            pid_t sender_tid;
            pid_t target_pid;
            pid_t target_tid;
            int signal;
            int ret;
        } signal;
    };
};
