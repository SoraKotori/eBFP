#include <iostream>
#include <memory>
#include <unordered_map>
#include <functional>
#include <iterator>
#include <ranges>
#include <print>

#include <bpf/libbpf.h>

#include "signal.h"
#include "signal.skel.h"

// bool is_pattern(const char *const command, const char *const pattern)
// {
//     return pattern[0] == '\0';
// }

struct argument
{
    std::size_t argc = 0;
    std::vector<std::string> argv;
    int ret = 0;
};

class sys_enter_execve_handler
{
    std::unordered_map<__u64, argument>& map_;

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
    std::unordered_map<__u64, argument>& map_;

public:
    sys_exit_execve_handler(decltype(map_) map) :
        map_{map}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_exit_execve_event*>(data);

        auto& arg = map_[event->pid_tgid];
        arg.ret = event->ret;

        std::print("pid: {} tid: {} ret: {:>2} command: ", 
            static_cast<unsigned>(event->pid_tgid >> 32),  // pid
            static_cast<unsigned>(event->pid_tgid),        // tid
            arg.ret);  // `{:>2}` 代表**右對齊、最小2格**
 
        std::ranges::copy(arg.argv, std::ostream_iterator<decltype(arg.argv)::value_type>{std::cout, " "});
        std::cout << '\n';
    }
};

static void handle_sys_enter_kill(int cpu, void *data, __u32 size)
{
    auto event = static_cast<sys_enter_kill_event*>(data);

    std::cout << "-----"                             << '\n';
    std::cout << "CPU: "        << cpu               << '\n';
    std::cout << "Sender PID: " << event->sender_pid << '\n';
    std::cout << "Target PID: " << event->target_pid << '\n';
    std::cout << "Signal: "     << event->signal     << '\n';
}

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


    std::unordered_map<__u64, argument> execve_map;
    
    event_handler<EVENT_MAX> handler;
    handler[EVENT_ID(sys_enter_execve_event)] = sys_enter_execve_handler{execve_map};
    handler[EVENT_ID(sys_exit_execve_event)]  = sys_exit_execve_handler{execve_map};
    handler[EVENT_ID(sys_enter_kill_event)]   = handle_sys_enter_kill;

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
    while (true)
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