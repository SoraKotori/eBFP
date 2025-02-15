#include <iostream>
#include <memory>
#include <unordered_map>

#include "signal.h"
#include "signal.skel.h"

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct event *e = (struct event *)data;

    printf("-----\n");
    printf("CPU: %d\n", cpu);
    printf("Sender PID: %d\n", e->sender_pid);
    printf("Target PID: %d\n", e->target_pid);
    printf("Signal: %d\n", e->signal);
}

int main(int argc, char *argv[])
{
    using unique_signal_t = std::unique_ptr<signal_bpf, decltype(&signal_bpf::destroy)>;

    // 開啟 / 加載 eBPF skeleton
    unique_signal_t skeleton{signal_bpf::open_and_load(), &signal_bpf::destroy};
    if (skeleton == nullptr)
        return EXIT_FAILURE;

    // attach eBPF 程式到對應的 tracepoint
    if (auto error = signal_bpf::attach(skeleton.get()); error)
        return EXIT_FAILURE;


    std::unordered_map<pid_t, struct event> event_map;

    perf_buffer_opts pb_opts{ .sz = sizeof(perf_buffer_opts) };

    // 4. 建立 perf buffer
    std::unique_ptr<struct perf_buffer, decltype(&perf_buffer__free)> pb(perf_buffer__new(
        bpf_map__fd(skeleton->maps.events),
        8,              // page_cnt
        handle_event,   // sample_cb
        nullptr,        // lost_cb
        NULL,           // ctx
        &pb_opts        // 其他選項
    ), &perf_buffer__free);
    if (pb == nullptr) {
        int error = -errno;
        fprintf(stderr, "Failed to create perf buffer: %d\n", error);
        return EXIT_FAILURE;
    }

    printf("Successfully started! Ctrl+C to stop.\n");

    // 5. 進入輪詢 loop
    while (true)
    {
        int error = perf_buffer__poll(pb.get(), 100 /* ms */);
        if (error < 0 && error != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", error);
            break;
        }
    }

    return 0;
}