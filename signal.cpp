#include <iostream>
#include <memory>
#include <unordered_map>
#include <functional>
#include <iterator>
#include <ranges>

#include <bpf/libbpf.h>

#include "signal.h"
#include "signal.skel.h"

// bool is_pattern(const char *const command, const char *const pattern)
// {
//     return pattern[0] == '\0';
// }

class command_event_handler
{
    struct argument
    {
        std::size_t argc = 0;
        std::vector<std::string> argv;
    };

    std::unordered_map<__u64, argument> map;

public:
    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<command_event*>(data);

        auto& arg = map[event->ktime];
        if (size > offsetof(command_event, argv_i))
        {
            arg.argv.emplace_back(event->argv_i, size - offsetof(command_event, argv_i) - 1); // not include '\0'
        }
        else
        {
            arg.argc = event->i;
            std::ranges::copy(arg.argv, std::ostream_iterator<decltype(arg.argv)::value_type>{std::cout, " "});
            std::cout << std::endl;
        }
    }
};

static void handle_signal_event(int cpu, void *data, __u32 size)
{
    auto event = static_cast<signal_event*>(data);

    std::cout << "-----"                             << std::endl;
    std::cout << "CPU: "        << cpu               << std::endl;
    std::cout << "Sender PID: " << event->sender_pid << std::endl;
    std::cout << "Target PID: " << event->target_pid << std::endl;
    std::cout << "Signal: "     << event->signal     << std::endl;
}

template<std::size_t number>
class event_handler
{
    std::array<std::function<void(int, void*, __u32)>, number> handlers_{};

    void handle_event(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<event_base*>(data);

        if (handlers_[event->id])
            handlers_[event->id](cpu, data, size);
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

    event_handler<__NR_kill + 1> handler;
    handler[__NR_execve] = command_event_handler{};
    handler[__NR_kill]   = handle_signal_event;

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