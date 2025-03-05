#include <iostream>
#include <memory>
#include <unordered_map>

#include <bpf/libbpf.h>

#include "signal.h"
#include "signal.skel.h"

static void handle_command_event(bpf_map *commands, const auto& event)
{
    char command[MAX_ARG_LEN];
    if (0 > bpf_map__lookup_elem(commands,
                                 &event.command.pid, sizeof(event.command.pid),
                                 command, sizeof(command),0))
        return;

    std::cout << command << std::endl;
}

static void handle_signal_event(int cpu, const auto& event)
{
    std::cout << "-----"                             << std::endl;
    std::cout << "CPU: "        << cpu               << std::endl;
    std::cout << "Sender PID: " << event.signal.sender_pid << std::endl;
    std::cout << "Target PID: " << event.signal.target_pid << std::endl;
    std::cout << "Signal: "     << event.signal.signal     << std::endl;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    auto& maps  = *static_cast<decltype(((signal_bpf*)0)->maps)*>(ctx);
    auto& event = *static_cast<struct event*>(data);

    switch (event.id)
    {
    case __NR_execve:
        handle_command_event(maps.commands, event);
        break;
    case __NR_kill:
        handle_signal_event(cpu, event);
        break;
    default:
        break;
    }
}

int main(int argc, char *argv[])
{
    // open and load eBPF skeleton
    auto skeleton = std::unique_ptr<signal_bpf, decltype(&signal_bpf::destroy)>{
                            signal_bpf::open_and_load(), &signal_bpf::destroy};
    if  (skeleton == nullptr)
        return EXIT_FAILURE;

    // update pattern to bpf map
    __u32 key = 0;
    char pattern[MAX_ARG_LEN] = "";
    if (0 > bpf_map__update_elem(skeleton->maps.command_pattern,
                                 &key, sizeof(key),
                                 pattern, sizeof(pattern), BPF_ANY))
        return EXIT_FAILURE;

    // attach eBPF 程式到對應的 tracepoint
    if (auto error = signal_bpf::attach(skeleton.get()); error)
        return EXIT_FAILURE;

    // perf buffer 選項
    perf_buffer_opts pb_opts{ .sz = sizeof(perf_buffer_opts) };

    // 建立 perf buffer
    auto perf_buffer_ptr = std::unique_ptr<perf_buffer, decltype(&perf_buffer__free)>{
        perf_buffer__new(bpf_map__fd(skeleton->maps.events),
                         8,
                         handle_event,
                         nullptr,
                         &skeleton->maps,
                         &pb_opts),
        &perf_buffer__free
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