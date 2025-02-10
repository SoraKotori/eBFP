#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

struct event {
    pid_t pid;
    pid_t target_pid;
    int signal;
    int ret;
    char comm[TASK_COMM_LEN];
};
