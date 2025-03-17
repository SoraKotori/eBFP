#include <csignal>

#include <iostream>
#include <memory>
#include <unordered_map>
#include <functional>
#include <iterator>
#include <ranges>
#include <print>
#include <coroutine>

#include <sys/wait.h>

#include <bpf/libbpf.h>
#include <blazesym.h>

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

void print_stack_trace(blaze_symbolizer* symbolizer, std::array<__u64, PERF_MAX_STACK_DEPTH>& stack, uint32_t tgid)
{
    blaze_symbolize_src_process src =
    {
        .type_size = sizeof(src),
        .pid = tgid,
        .debug_syms = true,
        .perf_map  = true,
        .map_files = true
    };

    static_assert(sizeof(uint64_t) == sizeof(typename std::remove_cvref_t<decltype(stack)>::value_type));

    auto syms = std::unique_ptr<const blaze_syms, decltype(&blaze_syms_free)>{
        blaze_symbolize_process_abs_addrs(symbolizer,
                                          &src,
                                          reinterpret_cast<uint64_t*>(std::data(stack)),
                                          std::size(stack)),
        blaze_syms_free};
    if (!syms)
    {
        std::println("blaze_symbolize_process_abs_addrs error: {}", blaze_err_str(blaze_err_last()));

        for(std::size_t i = 0; i < std::size(stack); i++)
            std::println("    #{:2} {:#018x}", i, stack[i]);

        return;
    }

    for(std::size_t i = 0; i < std::size(stack); i++)
    {
        std::println("    #{:2} {:#018x} name: {}, addr: {}, offset: {}", i, stack[i],
            syms->syms[i].name ? syms->syms[i].name : "null",
            syms->syms[i].addr,
            syms->syms[i].offset);
    }
}

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

        if (event->argv_i_size)
        {
            if (event->i == 0)
            {
                arg.argc = 0;
                arg.argv.clear();
                arg.ret = 0;
            }

            if (event->i == std::size(arg.argv))
                arg.argv.emplace_back(event->argv_i, event->argv_i_size - 1); // not include '\0'
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

        std::print("pid: {}, tid: {}, execve, ret: {:>2}, command: ", 
            event->tgid, // pid
            event->pid,  // tid
            event->ret); // {:>2} 代表右對齊、最小2格
 
        auto& arg = map_[event->pid_tgid];
        arg.ret = event->ret;

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

        std::println("pid: {}, tid: {}, kill, ret: {:>2}, target pid: {}, signal: {}", 
            event->tgid, // pid
            event->pid,  // tid
            event->ret,  // {:>2} 代表右對齊、最小2格
            arg.target_pid,
            arg.signal);

        arg.ret = event->ret;
    }
};

using read_argument = std::vector<char>;

class sys_enter_read_handler
{
    std::unordered_map<__u64, std::vector<char>>& map_;

public:
    sys_enter_read_handler(std::unordered_map<__u64, std::vector<char>>& map) :
        map_{map}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_enter_read_event*>(data);

        auto& buffer = map_[event->pid_tgid];

        auto result = std::begin(buffer) + event->index;
        result = std::copy_n(event->buf, event->size, result);

        if (result == end(buffer))
        {
            std::copy(std::begin(buffer), end(buffer), std::ostreambuf_iterator<char>(std::cout));
            std::println();
        }
    }
};

class sys_exit_read_handler
{
    std::unordered_map<__u64, std::vector<char>>& map_;
    blaze_symbolizer* symbolizer_;
    bpf_map* stack_trace_;

public:
    sys_exit_read_handler(std::unordered_map<__u64, std::vector<char>>& map,
                          blaze_symbolizer* symbolizer, bpf_map* stack_trace) :
        map_{map},
        symbolizer_{symbolizer},
        stack_trace_{stack_trace}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_exit_read_event*>(data);

        std::println("pid: {:>6}, tid: {:>6}, read, ret: {:>5}", 
            event->tgid, // pid
            event->pid,  // tid
            event->ret); // {:>2} 代表右對齊、最小2格

        if (event->ret > 0)
        {
            map_[event->pid_tgid].resize(event->ret);
        }
        
        // if (event->ret < 0)
        // {

        //     std::array<__u64, PERF_MAX_STACK_DEPTH> stack;
        //     int error = bpf_map__lookup_elem(stack_trace_,
        //                                      &event->stack_id, sizeof(event->stack_id),
        //                                      std::data(stack), sizeof(stack), 0);
        //     if (error < 0)
        //         return;

        //     print_stack_trace(symbolizer_, stack, event->tgid);
        // }
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
            sigabbrev_np(WTERMSIG(status)) ? sigabbrev_np(WTERMSIG(status)) : "null",
            sigdescr_np (WTERMSIG(status)) ? sigdescr_np (WTERMSIG(status)) : "null",
            WCOREDUMP(status) ? ", (core dumped)" : ""); // 判斷是否發生 Core Dump
}

class do_coredump_handler
{
    blaze_symbolizer* symbolizer_;
    bpf_map* stack_trace_;

public:
    do_coredump_handler(blaze_symbolizer* symbolizer, bpf_map* stack_trace) :
        symbolizer_{symbolizer},
        stack_trace_{stack_trace}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<do_coredump_event*>(data);

        std::array<__u64, PERF_MAX_STACK_DEPTH> stack;
        int error = bpf_map__lookup_elem(stack_trace_,
                                         &event->stack_id, sizeof(event->stack_id),
                                         std::data(stack), sizeof(stack), 0);
        if (error < 0)
            return;

        for (auto [i, address] : std::ranges::enumerate_view(stack))
        {
            if (address == 0)
                break;

            std::println("    #{} {:#018x}", i, address);
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

    // open eBPF skeleton
    auto skeleton = std::unique_ptr<signal_bpf, decltype(&signal_bpf::destroy)>{
                                    signal_bpf::open(),   signal_bpf::destroy};
    if (!skeleton)
        return EXIT_FAILURE;

    int error = 0;

    bool disable_read = true;
    
    if (disable_read)
    {
        if ((error = bpf_program__set_autoload(skeleton->progs.tracepoint__syscalls__sys_enter_read, false)) < 0)
            return EXIT_FAILURE;
        if ((error = bpf_program__set_autoload(skeleton->progs.tracepoint__syscalls__sys_exit_read, false)) < 0)
            return EXIT_FAILURE;
    }

    // load eBPF skeleton
    if ((error = signal_bpf::load(skeleton.get())) < 0)
        return EXIT_FAILURE;

    // update pattern to bpf map
    __u32 key = 0;
    char pattern[MAX_ARG_LEN] = "";
    if ((error = bpf_map__update_elem(skeleton->maps.command_pattern,
                                      &key, sizeof(key),
                                      pattern, sizeof(pattern), BPF_ANY)) < 0)
        return EXIT_FAILURE;

    // attach eBPF 程式到對應的 tracepoint
    if ((error = signal_bpf::attach(skeleton.get())) < 0)
        return EXIT_FAILURE;


    std::unordered_map<__u64, execve_argument> execve_map;
    std::unordered_map<__u64, kill_argument> kill_map;
    std::unordered_map<__u64, read_argument> read_map;
    
    auto symbolizer = std::unique_ptr<blaze_symbolizer, decltype(&blaze_symbolizer_free)>{
        blaze_symbolizer_new(),
        blaze_symbolizer_free};
    if (!symbolizer)
    {
        std::println("blaze_symbolizer_new error: {}", blaze_err_str(blaze_err_last()));
        return EXIT_FAILURE;
    }

    event_handler<EVENT_MAX> handler;
    handler[EVENT_ID(sys_enter_execve_event)]   = sys_enter_execve_handler{execve_map};
    handler[EVENT_ID(sys_exit_execve_event)]    = sys_exit_execve_handler{execve_map};
    handler[EVENT_ID(sys_enter_kill_event)]     = sys_enter_kill_handler{kill_map};
    handler[EVENT_ID(sys_exit_kill_event)]      = sys_exit_kill_handler{kill_map};
    handler[EVENT_ID(sys_enter_read_event)]     = sys_enter_read_handler{read_map};
    handler[EVENT_ID(sys_exit_read_event)]      = sys_exit_read_handler{read_map, symbolizer.get(), skeleton->maps.stack_trace};
    handler[EVENT_ID(sched_process_exit_event)] = handle_sched_process_exit;
    handler[EVENT_ID(do_coredump_event)]        = do_coredump_handler{symbolizer.get(), skeleton->maps.stack_trace};
    
    // perf buffer 選項
    perf_buffer_opts pb_opts{ .sz = sizeof(perf_buffer_opts) };

    // 建立 perf buffer 
    auto perf_buffer_ptr = std::unique_ptr<perf_buffer, decltype(&perf_buffer__free)>{
        perf_buffer__new(bpf_map__fd(skeleton->maps.events),
                         64,
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