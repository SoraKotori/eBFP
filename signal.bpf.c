#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "signal.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key_size, sizeof(pid_t));
    __type(value_size, sizeof(struct event));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
    pid_t target_pid = (pid_t)ctx->args[0];
    int sig = (int)ctx->args[1];

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct event event = {};
    event.pid = pid_tgid >> 32;
    event.target_pid = target_pid;
    event.signal = sig;

    bpf_get_current_comm(event.comm, sizeof(event.comm));
    bpf_map_update_elem(&values, &tid, &event, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct event *eventp = bpf_map_lookup_elem(&values, &tid);
    if (!eventp)
        return 0;

    eventp->ret = ctx->ret;
    bpf_printk("PID %d (%s) sent signal %d ", eventp->pid, eventp->comm, eventp->signal);
    bpf_printk("to PID %d, ret = %d", eventp->target_pid, ctx->ret);

cleanup:
    bpf_map_delete_elem(&values, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
