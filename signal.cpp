#include <iostream>
#include <memory>

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
    printf("Comm: %s\n", e->comm);
}

int main(int argc, char *argv[])
{
    using unique_signal_t = std::unique_ptr<signal_bpf, decltype(&signal_bpf::destroy)>;

    // 開啟 / 加載 eBPF skeleton
    unique_signal_t skel{signal_bpf::open_and_load(), &signal_bpf::destroy};
    if (skel == nullptr)
        return EXIT_FAILURE;

    // attach eBPF 程式到對應的 tracepoint
    if (auto error = signal_bpf::attach(skel.get()); error)
        return EXIT_FAILURE;

    struct perf_buffer_opts pb_opts = {
        .sz = sizeof(struct perf_buffer_opts),
        // 您可視需要設定 .sample_period 等欄位
    };

    int err;
    // 4. 建立 perf buffer
    struct perf_buffer *pb = perf_buffer__new(
        bpf_map__fd(skel->maps.events),
        8,              // page_cnt
        handle_event,   // sample_cb
        nullptr,    // lost_cb (如果不需要可填 NULL)
        NULL,           // ctx
        &pb_opts        // 其他選項
    );
    if (!pb) {
        int err = -errno;
        fprintf(stderr, "Failed to create perf buffer: %d\n", err);
        goto cleanup;
    }

    printf("Successfully started! Ctrl+C to stop.\n");

    // 5. 進入輪詢 loop
    while (true) {
        int err = perf_buffer__poll(pb, 100 /* ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    // 5. 收尾階段
    perf_buffer__free(pb);
    return 0;
}