#include <csignal>

#include <iostream>
#include <memory>
#include <unordered_map>
#include <functional>
#include <iterator>
#include <ranges>
#include <print>
#include <coroutine>

#include <bpf/libbpf.h>

#include <sys/wait.h>

#include "signal.h"
#include "signal.skel.h"

namespace
{
    volatile std::sig_atomic_t g_signal_status;
}

void signal_handler(int signal)
{
    g_signal_status = signal;
}

struct event_awaiter
{
    bool await_ready() const
    {
        // not ready, need suspend
        return false;
    }

    bool await_suspend(std::coroutine_handle<> handle)
    {
        // yes, suspend
        return true;
    }

    void await_resume()
    {
        return;
    }
};

// Task coroutine2(std::unordered_map<__u64, argument>& map)
// {

// }

// Task coroutine1(std::unordered_map<__u64, execve_argument>& map)
// {
//     while (true)
//     {
//         auto event = co_await static_cast<sys_enter_execve_event*>(data);

//         if (size > offsetof(sys_enter_execve_event, argv_i))
//         {
//             if (event->i == 0)
//             {
//                 arg.argc = 0;
//                 arg.argv.clear();
//                 arg.ret = 0;
//             }

//             if (event->i == std::size(arg.argv))
//                 arg.argv.emplace_back(event->argv_i, static_cast<char*>(data) + size - 1); // not include '\0'
//         }
//         else
//             arg.argc = event->i;
//     }
// }

struct execve_argument
{
    std::size_t argc = 0;
    std::vector<std::string> argv;
    int ret = 0;
};

class sys_enter_execve_handler
{
    std::unordered_map<__u64, execve_argument>& map_;

public:
    sys_enter_execve_handler(decltype(map_) map) :
        map_{map}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_enter_execve_event*>(data);

        auto& arg = map_[event->pid_tgid];

        if (size > offsetof(sys_enter_execve_event, argv_i))
        {
            if (event->i == 0)
            {
                arg.argc = 0;
                arg.argv.clear();
                arg.ret = 0;
            }

            if (event->i == std::size(arg.argv))
                arg.argv.emplace_back(event->argv_i, static_cast<char*>(data) + size - 1); // not include '\0'
        }
        else
            arg.argc = event->i;
    }
};

class sys_exit_execve_handler
{
    std::unordered_map<__u64, execve_argument>& map_;

public:
    sys_exit_execve_handler(decltype(map_) map) :
        map_{map}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_exit_execve_event*>(data);

        auto& arg = map_[event->pid_tgid];
        arg.ret = event->ret;

        std::print("pid: {}, tid: {}, ret: {:>2}, command: ", 
            event->tgid, // pid
            event->pid,  // tid
            arg.ret);    // {:>2} 代表右對齊、最小2格
 
        std::ranges::copy(arg.argv, std::ostream_iterator<decltype(arg.argv)::value_type>{std::cout, " "});
        std::cout << '\n';
    }
};

struct kill_argument
{
    __u32 target_pid = 0;
    int signal = 0;
    int ret = 0;
};

class sys_enter_kill_handler
{
    std::unordered_map<__u64, kill_argument>& map_;

public:
    sys_enter_kill_handler(decltype(map_) map) :
        map_{map}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_enter_kill_event*>(data);
        map_[event->pid_tgid] = kill_argument
                                {
                                    .target_pid = event->target_pid,
                                    .signal = event->signal,
                                    .ret = 0
                                };
    }
};

class sys_exit_kill_handler
{
    std::unordered_map<__u64, kill_argument>& map_;

public:
    sys_exit_kill_handler(decltype(map_) map) :
        map_{map}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_exit_kill_event*>(data);
        auto& arg = map_[event->pid_tgid];

        arg.ret = event->ret;

        std::println("pid: {}, tid: {}, ret: {:>2}, target pid: {}, signal: {}", 
            event->tgid, // pid
            event->pid,  // tid
            arg.ret,     // {:>2} 代表右對齊、最小2格
            arg.target_pid,
            arg.signal);
    }
};

void handle_sched_process_exit(int cpu, void *data, __u32 size)
{
    auto event = static_cast<sched_process_exit_event*>(data);

    std::print("pid: {}, tid: {}, ", 
        event->tgid, // pid
        event->pid); // tid

    auto status = event->exit_code;
    
    if (WIFEXITED(status))
        std::println("exited, exit code: {}", WEXITSTATUS(status));

    else if (WIFSIGNALED(status))
        std::println("killed by signal {} SIG{} ({}){}",
            WTERMSIG(status),
            sigabbrev_np(WTERMSIG(status)) ? sigabbrev_np(WTERMSIG(status)) : "NULL",
            sigdescr_np (WTERMSIG(status)) ? sigdescr_np (WTERMSIG(status)) : "NULL",
            WCOREDUMP(status) ? ", (core dumped)" : ""); // 判斷是否發生 Core Dump
}

class do_coredump_handler
{
    bpf_map* stack_trace_;

public:
    do_coredump_handler(bpf_map* stack_trace) :
        stack_trace_{stack_trace}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<do_coredump_event*>(data);

        std::array<__u64, PERF_MAX_STACK_DEPTH> stack;
        int error = bpf_map__lookup_elem(stack_trace_,
            &event->stack_id, sizeof(event->stack_id),
            stack.data(), sizeof(stack), 0);

        if (error < 0)
            return;

        for (auto [i, address] : std::ranges::enumerate_view(stack))
        {
            if (address == 0)
                break;

            std::println("#{} {:#018x} in {} ({})", i, address, "???", "???");
        }
    }
};

template<std::size_t number>
class event_handler
{
    std::array<std::function<void(int, void*, __u32)>, number> handlers_{};

    void handle_event(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<event_base*>(data);

        if (handlers_[event->event_id])
            handlers_[event->event_id](cpu, data, size);
    }

public:
    using value_type      = typename decltype(handlers_)::value_type;
    using size_type       = typename decltype(handlers_)::size_type;
    using reference       = typename decltype(handlers_)::reference;
    using const_reference = typename decltype(handlers_)::const_reference;

    constexpr reference operator[](size_type n) noexcept
    {
        return handlers_[n];
    }

    constexpr const_reference operator[](size_type n) const noexcept
    {
        return handlers_[n];
    }

    static void callback(void* ctx, int cpu, void* data, __u32 size)
    {
        auto handler = static_cast<event_handler*>(ctx);

        // 呼叫實際的 member function
        handler->handle_event(cpu, data, size);
    }
};

int main(int argc, char *argv[])
{
    if (SIG_ERR == std::signal(SIGINT,  signal_handler)) return EXIT_FAILURE;
    if (SIG_ERR == std::signal(SIGTERM, signal_handler)) return EXIT_FAILURE;

    // open and load eBPF skeleton
    auto skeleton = std::unique_ptr<signal_bpf, decltype(&signal_bpf::destroy)>{
                             signal_bpf::open_and_load(), signal_bpf::destroy};
    if (!skeleton)
        return EXIT_FAILURE;

    // update pattern to bpf map
    __u32 key = 0;
    char pattern[MAX_ARG_LEN] = "";
    auto error = bpf_map__update_elem(skeleton->maps.command_pattern,
                                      &key, sizeof(key),
                                      pattern, sizeof(pattern), BPF_ANY);
    if (error < 0)
        return EXIT_FAILURE;

    // attach eBPF 程式到對應的 tracepoint
    if ((error = signal_bpf::attach(skeleton.get())) < 0)
        return EXIT_FAILURE;


    std::unordered_map<__u64, execve_argument> execve_map;
    std::unordered_map<__u64, kill_argument> kill_map;
    
    event_handler<EVENT_MAX> handler;
    handler[EVENT_ID(sys_enter_execve_event)]   = sys_enter_execve_handler{execve_map};
    handler[EVENT_ID(sys_exit_execve_event)]    = sys_exit_execve_handler{execve_map};
    handler[EVENT_ID(sys_enter_kill_event)]     = sys_enter_kill_handler{kill_map};
    handler[EVENT_ID(sys_exit_kill_event)]      = sys_exit_kill_handler{kill_map};
    handler[EVENT_ID(sched_process_exit_event)] = handle_sched_process_exit;
    handler[EVENT_ID(do_coredump_event)]        = do_coredump_handler{skeleton->maps.stack_trace};
    
    // perf buffer 選項
    perf_buffer_opts pb_opts{ .sz = sizeof(perf_buffer_opts) };

    // 建立 perf buffer 
    auto perf_buffer_ptr = std::unique_ptr<perf_buffer, decltype(&perf_buffer__free)>{
        perf_buffer__new(bpf_map__fd(skeleton->maps.events),
                         8,
                         handler.callback,
                         nullptr,
                         &handler,
                         &pb_opts),
        perf_buffer__free
    };

    if (perf_buffer_ptr == nullptr)
    {
        int error = -errno;
        fprintf(stderr, "Failed to create perf buffer: %d\n", error);
        return EXIT_FAILURE;
    }

    printf("Successfully started! Ctrl+C to stop.\n");

    // 進入 poll loop
    while (!g_signal_status)
    {
        int error = perf_buffer__poll(perf_buffer_ptr.get(), 100 /* ms */);
        if (error < 0 && error != -EINTR)
        {
            fprintf(stderr, "Error polling perf buffer: %d\n", error);
            break;
        }
    }

    return 0;
}