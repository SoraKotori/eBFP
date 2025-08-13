#include <fcntl.h>
#include <unistd.h>
#include <csignal>

#include <iostream>
#include <memory>
#include <unordered_map>
#include <functional>
#include <iterator>
#include <ranges>
#include <print>
#include <coroutine>
#include <algorithm>
#include <span>
#include <set>
#include <chrono>
#include <type_traits>
#include <cstring>
#include <syncstream>

#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <dirent.h>

#include <bpf/libbpf.h>
#include <blazesym.h>

struct path
{
    void *mnt;
    void *dentry;
    auto operator<=>(const path&) const = default;
};

struct path_hash
{
    std::size_t operator()(const path& path) const
    {
        // 先對每個成員做 std::hash
        std::size_t h1 = std::hash<decltype(path.mnt)>{}(path.mnt);
        std::size_t h2 = std::hash<decltype(path.dentry)>{}(path.dentry);

        // 簡單的「XOR + 移位」混合做法：
        // 這裡 0x9e3779b97f4a7c15ULL 是常見的「黃金比例」常數
        // 只是一種常見的雜湊結合技巧，讓結果分佈更均勻
        return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
    }
};

#include "signal.h"
#include "signal.skel.h"
#include "waitable_map.hpp"
#include "syscall_name_to_nr.h"

namespace
{
    volatile std::sig_atomic_t g_signal_status;
}

void signal_handler(int signal)
{
    g_signal_status = signal;
}

// template<typename T, std::size_t Extent = std::dynamic_extent>
// void print_stack_trace(blaze_symbolizer* symbolizer,
//                        std::span<T, Extent> addrs)
// {

// }

template<typename T, std::size_t Extent = std::dynamic_extent>
void print_stack_trace(blaze_normalizer* normalizer,
                       blaze_symbolizer* symbolizer,
                       uint32_t tgid,
                       std::span<T, Extent> addrs)
{
    // blaze_normalize_opts opts =
    // {
    //     .type_size = sizeof(opts)
    // };

    // auto output = std::unique_ptr<blaze_normalized_user_output, decltype(&blaze_user_output_free)>{
    //     blaze_normalize_user_addrs_opts(normalizer,
    //                                     tgid,
    //                                     reinterpret_cast<uint64_t*>(std::data(addrs)),
    //                                     std::size(addrs),
    //                                     &opts),
    //     blaze_user_output_free};
    // if (!output)
    // {
    //     std::println(std::cout, "blaze_normalize_user_addrs_opts: {}", blaze_err_str(blaze_err_last()));
    //     return;
    // }

    // for (std::size_t i = 0; i < std::size(addrs); i++)
    // {
    //     const auto& meta = output->metas[output->outputs[i].meta_idx];

    //     if      (meta.kind == blaze_user_meta_kind::BLAZE_USER_META_UNKNOWN)
    //     {
    //         std::println(std::cout, "    {:>2}, abs_addr: {:>#18x}, {}",
    //             i, addrs[i],
    //             blaze_normalize_reason_str(meta.variant.unknown.reason));
    //     }
    //     else if (meta.kind == blaze_user_meta_kind::BLAZE_USER_META_APK)
    //     {
    //         std::println(std::cout, "    {:>2}, abs_addr: {:>#18x}, apk: {:40} apk_off: {:>#10x}",
    //             i, addrs[i],
    //             std::format("\"{}\"", meta.variant.apk.path),
    //             output->outputs[i].output);
    //     }
    //     else if (meta.kind == blaze_user_meta_kind::BLAZE_USER_META_ELF)
    //     {
    //         std::print(std::cout, "    {:>2}, abs_addr: {:>#18x}, elf: {:40} elf_off: {:>#10x}",
    //             i, addrs[i],
    //             std::format("\"{}\"", meta.variant.elf.path),
    //             output->outputs[i].output);

    //         // struct bpf_stack_build_id id_off;

    //         blaze_symbolize_src_elf src =
    //         {
    //             .type_size  = sizeof(src),
    //             .path       = meta.variant.elf.path,
    //             .debug_syms = true
    //         };

    //         auto syms = std::unique_ptr<const blaze_syms, decltype(&blaze_syms_free)>{
    //             blaze_symbolize_elf_file_offsets(symbolizer,
    //                                              &src,
    //                                              &output->outputs[i].output,
    //                                              1),
    //             blaze_syms_free};

    //         if (syms)
    //         {
    //             const auto& sym = syms->syms[0];
    //             if (sym.reason)
    //                 std::print(std::cout, ", \"{}\"", blaze_symbolize_reason_str(sym.reason));
    //             else
    //             {
    //                 std::print(std::cout, ", sym: {}, sym_addr: {:#010x}, sym_off: {:#010x}",
    //                     sym.name,
    //                     sym.addr,
    //                     sym.offset);

    //                 if (sym.code_info.file)
    //                     std::print(std::cout, ", file: {}:{}:{}",
    //                         sym.code_info.file,
    //                         sym.code_info.line,
    //                         sym.code_info.column);
    //             }
    //         }
    //         else
    //         {
    //             std::print(std::cout, ", {}", blaze_err_str(blaze_err_last()));
    //         }

    //         std::println(std::cout);
    //     }
    // }

    blaze_symbolize_src_process src =
    {
        .type_size = sizeof(src),
        .pid = tgid,
        .debug_syms = true,
        // .perf_map  = true
        // .map_files = true
    };

    static_assert(sizeof(uint64_t) == sizeof(typename std::remove_cvref_t<decltype(addrs)>::value_type));

    auto syms = std::unique_ptr<const blaze_syms, decltype(&blaze_syms_free)>{
        blaze_symbolize_process_abs_addrs(symbolizer,
                                          &src,
                                          reinterpret_cast<uint64_t*>(std::data(addrs)),
                                          std::size(addrs)),
        blaze_syms_free};
    if (!syms)
    {
        std::println(std::cout, "blaze_symbolize_process_abs_addrs: {}", blaze_err_str(blaze_err_last()));

        for(std::size_t i = 0; i < std::size(addrs); i++)
            std::println(std::cout, "    #{:<2} {:#014x}", i, addrs[i]);

        return;
    }

    // sudo eBFP/blazesym/target/debug/blazecli symbolize process --pid 259062 0x005642ad65d095
    // 0x005642ad65d095: _start @ 0x1070+0x25

    for(std::size_t i = 0; i < std::size(addrs); i++)
    {
        std::print(std::cout, "    #{:<2} {:#014x} in {:<20}",
            i, addrs[i],
            syms->syms[i].name ? syms->syms[i].name : "null");

        if (syms->syms[i].reason)
            std::println(std::cout, " {}", blaze_symbolize_reason_str(syms->syms[i].reason));
        else
            std::println(std::cout, " sym_addr: {:#014x}, sym_off: {:#010x}, name: {}:{}:{}",
                syms->syms[i].addr,
                syms->syms[i].offset,
                syms->syms[i].code_info.file ? syms->syms[i].code_info.file : "null",
                syms->syms[i].code_info.line,
                syms->syms[i].code_info.column);
    }
}

struct execve_argument
{
    std::optional<long>      ret;
    std::optional<__u32>     argc;
    std::vector<std::string> argv;

    auto println(__u32 tgid, __u32 pid, int cpu) const
    {
        std::print(std::cout, "pid: {:>6}, tid: {:>6}, execve,  cpu: {}, ret: {:>5}, argc: {}, argv: [\"{}\"",
            tgid, pid, cpu, ret.value(), argc.value(), argv.front());

        for (const auto& arg : argv | std::views::drop(1))
            std::print(std::cout, ", \"{}\"", arg);

        std::println(std::cout, "]");

        if (argc.value() == MAX_ARGV_UNROLL)
            std::println(std::cout, "warning: execve argv count reached limit ({}), possible truncation", MAX_ARGV_UNROLL);
    }
};

class execve_event_handler
{
    std::unordered_map<__u64, execve_argument> map_;

public:
    void enter(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_enter_execve_event*>(data);

        // 用 ktime 作為 key，把同一次 execve 的 enter/exit 事件綁在一起
        auto& argument = map_[event->ktime];

        if (event->argv_i_size)
            if (event->i == std::size(argument.argv))
                // eBPF 會把 argv 分多段傳送
                argument.argv.emplace_back(event->argv_i, event->argv_i_size - 1);
            else
                std::println(std::cout, "pid: {:>6}, tid: {:>6}, execve, cpu: {}, warning: argv out of order",
                    event->tgid, event->pid, cpu);
        else
        {
            // 當最後一個 enter 事件的大小等於零，代表 argv 已經傳送完畢，
            // 記錄 execve 的參數數量
            argument.argc = std::size(argument.argv);

            // 由於 BPF 每個 CPU 各有獨立的 perf ring buffer，
            // 使用者空間讀取時，會同時輪詢多個 buffer，哪個可以讀就先處理哪個事件。
            // 如果 exit 事件（kretprobe）剛好跑到別的 CPU 先被讀取，
            // 那就會出現「exit 先於 enter」的情況。

            // 因此：當 enter 最後階段拿到 argc 之後，如果之前已經在 exit handler
            // 拿到 ret，則此時兩邊資料都齊全，才真正呼叫 println()。
            if (argument.ret)
                argument.println(event->tgid, event->pid, cpu);
        }
    }

    void exit(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_exit_execve_event*>(data);
        auto& argument = map_[event->ktime];

        // 記錄 execve 的 return value
        argument.ret = event->ret;

        // 同理，如果 enter 的參數剛好在另一個 ring buffer 還沒被讀取到，
        // 即使 exit handler 先拿到 ret 也不能直接列印。
        // 必須等到使用者空間接收到 enter 的 argument.argc 後，
        // 兩邊資料才算完整，這時才呼叫 println()。
        if (argument.argc)
            argument.println(event->tgid, event->pid, cpu);
    }
};

struct kill_argument
{
    std::optional<long> ret;
    __u32               target_pid;
    std::optional<int>  signal;

    auto println(__u32 tgid, __u32 pid, int cpu) const
    {
        std::println(std::cout, "pid: {:>6}, tid: {:>6}, kill,    ret: {:>5}, target pid: {}, signal: {}",
            tgid, pid, ret.value(), target_pid, signal.value());
    }
};

class kill_event_handler
{
    std::unordered_map<__u64, kill_argument> map_;

public:
    void enter(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_enter_kill_event*>(data);

        // 用 ktime 當 key 綁定同一次 kill 的 enter/exit
        auto& argument = map_[event->ktime];
        argument.target_pid = event->target_pid;
        argument.signal     = event->signal;

        // exit 可能先於 enter 到達，只有在 ret 已到才列印
        if (argument.ret)
            argument.println(event->tgid, event->pid, cpu);
    }

    void exit(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_exit_kill_event*>(data);

        auto& argument = map_[event->ktime];
        argument.ret = event->ret;

        // enter 可能先於 exit 到達，只有在 signal 已到才列印
        if (argument.signal)
            argument.println(event->tgid, event->pid, cpu);
    }
};

struct path_event_handler : public waitable_map<std::unordered_map, struct path, std::string, path_hash>
{
    const struct bpf_map *bpf_path_map_;
    bool print_name_ = true;

    auto ktime(const struct path &path, unsigned long long flags = 0) const
    {
        __u64 ktime;
        if (auto error = bpf_map__lookup_elem(bpf_path_map_,
                                              &path, sizeof(path),
                                              &ktime, sizeof(ktime), flags))
            throw std::system_error{-error, std::system_category(), "bpf_map__lookup_elem"};

        return ktime;
    }

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<path_event*>(data);

        std::string_view name
        {
            event->name + event->index,
            event->name + MAX_ARG_LEN - MAX_NAME_LEN
        };

        if (print_name_)
        {
            struct timespec tp;
            if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0)
                throw std::system_error{errno, std::system_category(), "clock_gettime"};

            auto path_ktime = ktime(event->path);
            std::println(std::cout, "pid: {:>6}, tid: {:>6}, path,    cpu: {}, latency: {}, mnt: {:p}, dentry: {:p}, name: \"{}\"",
                event->tgid,
                event->pid,
                cpu,
                tp.tv_sec * 1'000'000'000 + tp.tv_nsec - path_ktime,
                event->path.mnt,
                event->path.dentry,
                name);
        }

        // 用 path 當 key 插入從 event 取得的 path name
        auto [iterator, inserted] = try_emplace(event->path, name);

        // 如果 path 被重複插入時，印出 old/new name 的警告訊息
        if (!inserted)
            std::println(std::cout,
                "warning: path_event_handler.try_emplace.inserted == false\n"
                "    old name: {}\n"
                "    new name: {}", iterator->second, name);
    }
};

// read_argument: 用於蒐集同一次 read() 呼叫的參數與緩衝區內容
// 在同一個 eBPF 程式中，sys_exit_read 會先送出回傳值 (buffer 大小)
// 接著 sys_enter_read 再負責將實際讀取的內容填入 buffer
struct read_argument : public std::enable_shared_from_this<read_argument>
{
    long ret;
    int fd;
    __u16 i_mode;
    struct path path;
    std::vector<char> buffer;

    // 定義最大長度，eBPF 最大可傳送的大小
    static constexpr long max_size = MAX_READ_UNROLL * MAX_ARG_LEN;

    // 定義 ELF 檔的 magic number 
    static constexpr std::string_view elf_magic{"\177ELF"};

    Task<promise> println(__u32 tgid, __u32 pid, int cpu,
                          path_event_handler& path_handler) const
    {
        // 保持 *this 存活直到 coroutine 的生命週期結束
        [[maybe_unused]] auto self = shared_from_this();

        std::string_view mode;
        std::string permission(10, '-');

        // 判斷檔案類型，並設定 permission[0]
        if      (S_ISREG (i_mode)) { mode = "regular file";     permission[0] = '-'; }
        else if (S_ISDIR (i_mode)) { mode = "directory";        permission[0] = 'd'; }
        else if (S_ISCHR (i_mode)) { mode = "character device"; permission[0] = 'c'; }
        else if (S_ISBLK (i_mode)) { mode = "block device";     permission[0] = 'b'; }
        else if (S_ISFIFO(i_mode)) { mode = "FIFO/pipe";        permission[0] = 'p'; }
        else if (S_ISLNK (i_mode)) { mode = "symbolic link";    permission[0] = 'l'; }
        else if (S_ISSOCK(i_mode)) { mode = "socket";           permission[0] = 's'; }
        else                       { mode = "unknown";          permission[0] = '?'; }

        // 設定 rwx 權限
        if (S_IRUSR & i_mode) permission[1] = 'r';
        if (S_IWUSR & i_mode) permission[2] = 'w';
        if (S_IXUSR & i_mode) permission[3] = 'x';
        if (S_IRGRP & i_mode) permission[4] = 'r';
        if (S_IWGRP & i_mode) permission[5] = 'w';
        if (S_IXGRP & i_mode) permission[6] = 'x';
        if (S_IROTH & i_mode) permission[7] = 'r';
        if (S_IWOTH & i_mode) permission[8] = 'w';
        if (S_IXOTH & i_mode) permission[9] = 'x';

        // 特殊權限 (setuid/setgid/sticky bit)
        if (S_ISUID & i_mode) permission[3] = (i_mode & S_IXUSR) ? 's' : 'S';
        if (S_ISGID & i_mode) permission[6] = (i_mode & S_IXGRP) ? 's' : 'S';
        if (S_ISVTX & i_mode) permission[9] = (i_mode & S_IXOTH) ? 't' : 'T';

        // eBPF 在 path_tailcall 階段，會對首次出現的 path 先在 map 中設置 flag，然後才處理該 path。
        // 而本次 event 的 path_tailcall 會跳過已設 flag 的 path，但該 path 仍可能在其他 event 中處理。  
        // 因此必須等到其他 event 處理完畢並將 path 插入 map 後，再進行查找。
        auto path_iterator = co_await path_handler.async_find(path);

        std::println(std::cout, "pid: {:>6}, tid: {:>6}, read,    ret: {:>5}, fd: {:>3}, {} ({}), name: \"{}\"",
            tgid, pid, ret, fd, permission, mode, path_iterator->second);

        // 若有讀取到 context，並且不是 ELF 檔，則輸出文字內容
        if (std::size(buffer) &&
            std::end(elf_magic) != std::ranges::mismatch(buffer, elf_magic).in2)
        {
            // 如果 context 超出上限，就截斷並印出警告
            if (ret > max_size)
                std::println(std::cout, "warning: read size {} exceeds limit {}, truncating to {}",
                    ret, max_size, max_size);

            std::println(std::cout, "{}", std::string_view{std::begin(buffer), std::end(buffer)});
        }

        co_return;
    }
};

struct read_event_handler
{
    path_event_handler& path_handler_;
    __u32 context;

    std::unordered_map<__u64, std::shared_ptr<read_argument>> map_;

    void enter(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_enter_read_event*>(data);

        // 用 ktime 當 key 綁定同一次 read 的 enter/exit
        auto iterator = map_.find(event->ktime);
        if  (iterator == std::end(map_))
        {
            // 先執行的 exit 已經插入 ktime 在 map 中了，
            // 並且與 enter 在相同的 eBPF 程式中，理論上不會有 out-of-order 的情況
            std::println(std::cout, "warning: read_argument not found for ktime {}", event->ktime);
            return;
        }

        auto& buffer = iterator->second->buffer;

        // 將本次讀取的資料片段複製到 buffer
        // 如果 copy_n 回傳 buffer_end，代表已經接收完整 content
        if (std::end  (buffer) == std::copy_n(event->buf, event->size,
            std::begin(buffer) + event->index))
        {
            // 由於 buffer 會占用大量的記憶體，因此需要先提取釋放
            auto node = map_.extract(iterator);
            node.mapped()->println(event->tgid, event->pid, cpu, path_handler_);
        }
    }

    void exit(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_exit_read_event*>(data);

        auto argument = std::make_shared_for_overwrite<read_argument>();
        argument->ret    = event->ret;
        argument->fd     = event->fd;
        argument->i_mode = event->i_mode;
        argument->path   = event->path;

        if (context && event->ret > 0)
        {
            // 根據 return value 調整 buffer 大小，如果超出 max_size 上限則截斷
            argument->buffer.resize(std::min(event->ret, read_argument::max_size));

            // 用 ktime 當 key 綁定同一次 read 的 enter/exit
            if (map_.try_emplace(event->ktime, std::move(argument)).second == false)
                // ktime 重複的情況理論上不應該發生
                std::println(std::cout, "warning: failed to insert read_argument for ktime {}", event->ktime);
        }
        else
        {
            // 若 read_context 設為 false 或沒有 context 可以讀取，
            // 則不會傳送 enter event，提前印出 argument
            argument->println(event->tgid, event->pid, cpu, path_handler_);
        }
    }
};

struct vm_area_comp
{
    auto operator()(const vm_area_event::vm_area& left,
                    const vm_area_event::vm_area& right) const
    {
        return left.vm_start < right.vm_start;
    }
};

class vm_area_handler
{
    std::unordered_map<__u64, std::set<vm_area_event::vm_area, vm_area_comp>>& vm_area_map_;
    bool print_event_;
    bool print_area_;

    // 若能得知 cpu 數量，可以改用 std::vector
    std::unordered_map<int, __u64> ktime_map_;

public:
    template<typename... ktime_Args>
    vm_area_handler(decltype(vm_area_map_) vm_area_map,
                    decltype(print_event_) print_event,
                    decltype(print_area_)  print_area,
                    ktime_Args&&...        ktime_args) :
        vm_area_map_(vm_area_map),
        print_event_(print_area),
        print_area_(print_area),
        ktime_map_(std::forward<ktime_Args>(ktime_args)...)
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<vm_area_event*>(data);

        auto& areas = vm_area_map_[event->pid_tgid];

        // 同一 pid_tgid 可能連續收到多個 vm_area_event
        // 透過 cpu 與 ktime 判斷是否屬於同一批次：
        //  - ktime 與 cpu 均相同：同一批次，繼續累積
        //  - ktime 或 cpu 不同：視為新批次，需重置資料
        //
        // 由於不同 CPU 的 ktime 幾乎不會重複，故可用 cpu 代替 pid_tgid 比對對應的 ktime
        if (ktime_map_[cpu] != event->ktime)
        {
            ktime_map_[cpu]  = event->ktime;
            areas.clear();
        }

        auto hint = std::end(areas);
        for (const auto& area : std::span{event->area, event->area_size})
             hint = areas.emplace_hint(hint, area);

        // 在 vm_area 掃描中，記憶體區段會被分成多次 event 傳送：
        //  - 當前傳送的大小（area_size）等於 MAX_AREA 時，表示還有後續區段未傳送。
        //  - 當 area_size < MAX_AREA 時，表示最後一個區段已送達，整批 vm_area 才算完整。
        if (event->area_size == MAX_AREA)
            return;

        // 可考慮把這兩段 std::println 的呼叫移到 vm_area_argument 內處理。
        if (print_event_)
            std::println(std::cout, "pid: {:>6}, tid: {:>6}, vm_area, cpu: {}, size: {}",
                event->tgid,
                event->pid,
                cpu,
                std::size(areas));

        if (print_area_)
            for (const auto& entry : areas)
                std::println(std::cout, "    start: {:#x}, end: {:#x}, pgoff: {:#x}, mnt: {:p}, dentry: {:p}",
                    entry.vm_start,
                    entry.vm_end,
                    entry.vm_pgoff * 4096,
                    entry.path.mnt,
                    entry.path.dentry);
    }
};

void handle_sched_process_exit(int cpu, void *data, __u32 size)
{
    auto event = static_cast<sched_process_exit_event*>(data);

    std::print(std::cout, "pid: {:>6}, tid: {:>6}, ",
        event->tgid, // pid
        event->pid); // tid

    auto status = event->exit_code;

    if (WIFEXITED(status))
        std::println(std::cout, "exited,  ret: {:>5}", WEXITSTATUS(status));

    else if (WIFSIGNALED(status))
        std::println(std::cout, "killed,  ret: {:>5} SIG{} ({}){}",
            WTERMSIG(status),
            sigabbrev_np(WTERMSIG(status)) ? sigabbrev_np(WTERMSIG(status)) : "null",
            sigdescr_np (WTERMSIG(status)) ? sigdescr_np (WTERMSIG(status)) : "null",
            WCOREDUMP(status) ? ", (core dumped)" : ""); // 判斷是否發生 Core Dump
}

struct do_coredump_handler
{
    std::unordered_map<__u64, std::osyncstream>& osyncstream_map_;

    auto println(std::ostream &ostream, int cpu, const do_coredump_event *event) const
    {
        std::println(ostream, "pid: {:>6}, tid: {:>6}, syscall, cpu: {}, si_signo: {}, si_code: {}",
            event->tgid,
            event->pid,
            cpu,
            event->si_signo,
            event->si_code);
    }

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<do_coredump_event*>(data);

        // 若 ktime != 0，則代表後續接了其他的 event 所以需要先保存訊息之後再由其他 event 處理
        // 可以考慮改用 syscell_stack_map 作為判斷，並且在 event 中都填入 ktime
        if (event->ktime)
        {
            auto [iterator, inserted] = osyncstream_map_.try_emplace(event->ktime, std::cout);

            // ktime 重複的情況理論上不應該發生
            if (!inserted)
                std::println(iterator->second, "warning: failed to insert for ktime {}", event->ktime);

            println(iterator->second, cpu, event);
        }
        // 若 ktime == 0，則代表後面沒有串接其他 event 可以直接印出訊息
        else
            println(std::cout, cpu, event);
    }
};

struct exit_event_handler
{
    std::unordered_map<__u64, std::osyncstream>& osyncstream_map_;

    auto println(std::ostream &ostream, int cpu, const sys_exit_event *event) const
    {
        std::println(ostream, "pid: {:>6}, tid: {:>6}, syscall, cpu: {}, ret: {:>5}, number: {}",
            event->tgid,
            event->pid,
            cpu,
            event->ret,
            event->syscall_nr);
    }

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_exit_event*>(data);

        // 若 ktime != 0，則代表後續接了其他的 event 所以需要先保存訊息之後再由其他 event 處理
        // 可以考慮改用 syscell_stack_map 作為判斷，並且在 event 中都填入 ktime
        if (event->ktime)
        {
            auto [iterator, inserted] = osyncstream_map_.try_emplace(event->ktime, std::cout);

            // ktime 重複的情況理論上不應該發生
            if (!inserted)
                std::println(iterator->second, "warning: failed to insert for ktime {}", event->ktime);

            println(iterator->second, cpu, event);
        }
        // 若 ktime == 0，則代表後面沒有串接其他 event 可以直接印出訊息
        else
            println(std::cout, cpu, event);
    }
};

#ifndef MAX_ERRNO
#define MAX_ERRNO 4095
#endif

#ifndef IS_ERR_VALUE
#define IS_ERR_VALUE(x) ((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)
#endif

#ifndef PROT_READ
#define PROT_READ   0x1  /* Page can be read.  */
#endif

#ifndef MAP_PRIVATE
#define MAP_PRIVATE 0x02 /* Changes are private.  */
#endif

#ifndef MAP_FIXED
#define MAP_FIXED   0x10 /* Interpret addr exactly.  */
#endif

struct do_mmap_handler
{
    std::unordered_map<__u64, std::set<vm_area_event::vm_area, vm_area_comp>>& vm_area_map_;

    // 需要考慮 do_mmap_event 未到達時，後面的 event 已經在查詢 vm_area_map_ 的問題
    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<do_mmap_event*>(data);
        if (IS_ERR_VALUE(event->ret))
            return;

        // auto& areas = vm_area_map_[event->pid_tgid];

        // if (event->prot  == PROT_READ &&
        //     event->flags == (MAP_PRIVATE | MAP_FIXED) &&
        //     event->pgoff == 0)
        // {
        //     areas.clear();
        // }

        // auto [iterator, inserted] = areas.emplace(event->addr,
        //                                           event->addr + event->len,
        //                                           event->pgoff,
        //                                           event->path);

        // std::println(std::cout, "    "
        //     "tgid: {}, "
        //     "pid: {}, "
        //     "addr: {:x}, "
        //     "len: {}, "
        //     "prot: {}, "
        //     "flags: {}, "
        //     "pgoff: {:x}, "
        //     "uf: {:p}",
        //     event->tgid,
        //     event->pid,
        //     event->addr,
        //     event->len,
        //     event->prot,
        //     event->flags,
        //     event->pgoff,
        //     (void*)event->uf
        // );
    }
};

struct stack_handler
{
    blaze_normalizer* normalizer_;
    blaze_symbolizer* symbolizer_;
    const std::unordered_map<__u64, std::set<vm_area_event::vm_area, vm_area_comp>>& vm_area_map_;
    path_event_handler& path_handler_;

    // 次佳方案可能是用 std::function 或 coroutine 的方法延遲生成輸出內容
    std::unordered_map<__u64, std::osyncstream>& osyncstream_map_;

    void operator()(int cpu, void *data, __u32 size)
    {
        println(cpu, data, size);
    }

    Task<promise> println(int cpu, void *data, __u32 size)
    {
        // coroutine 可能會暫停，此時 data 會被釋放，
        // 因此必須先將原始資料複製到 local buffer 中，以確保之後存取依然有效
        auto buffer = std::make_unique_for_overwrite<std::byte[]>(size);
        auto event  = reinterpret_cast<stack_event*>(buffer.get());
        std::memcpy(event, data, size);

        // coroutine 可能中途暫停，若直接對 std::cout 輸出，容易與其他輸出互相交錯
        // 因此先將所有輸出暫存到 std::osyncstream，推遲到 destructor 在一次性地寫入
        auto  node = osyncstream_map_.extract(event->ktime);
        auto& ostream = node.mapped();

        const auto& areas = vm_area_map_.at(event->pid_tgid);
        const auto  addrs = std::span<unsigned long>{event->addrs, event->addr_size};
        for (const auto& addr : addrs)
        {
            vm_area_event::vm_area key = { .vm_start = addr };

            auto find_area = areas.upper_bound(key);
            if  (find_area == std::begin(areas) || (--find_area)->vm_end <= key.vm_start)
            {
                // addr: 0x000000f22ec4 elf: /root/.vscode-server/extensions/ms-vscode.cpptools-1.24.5-linux-x64/bin/cpptools-srv elf_off:   0xb22ec4, sym: std::__basic_file<char>::open(char const*, std::_Ios_Openmode, int), sym_addr: 0x00f22e90, sym_off: 0x00000034, file: basic_file.cc:260:16
                // warning: not find area, start: 0x7ffc5c58d000, end: 0x7ffc5c58f000, addr: 0x2567646573257325
                // addr: 0x000000f22ec4 elf: /root/.vscode-server/extensions/ms-vscode.cpptools-1.24.5-linux-x64/bin/cpptools-srv elf_off:   0xb22ec4, sym: std::__basic_file<char>::open(char const*, std::_Ios_Openmode, int), sym_addr: 0x00f22e90, sym_off: 0x00000034, file: basic_file.cc:260:16
                // warning: not find area, start: 0x7ffc632bd000, end: 0x7ffc632bf000, addr: 0x2567646573257325
                // addr: 0x000000f22ec4 elf: /root/.vscode-server/extensions/ms-vscode.cpptools-1.24.5-linux-x64/bin/cpptools-srv elf_off:   0xb22ec4, sym: std::__basic_file<char>::open(char const*, std::_Ios_Openmode, int), sym_addr: 0x00f22e90, sym_off: 0x00000034, file: basic_file.cc:260:16
                // warning: not find area, start: 0x7fff0eb5f000, end: 0x7fff0eb61000, addr: 0x2567646573257325
                // addr: 0x000000f22ec4 elf: /root/.vscode-server/extensions/ms-vscode.cpptools-1.24.5-linux-x64/bin/cpptools-srv elf_off:   0xb22ec4, sym: std::__basic_file<char>::open(char const*, std::_Ios_Openmode, int), sym_addr: 0x00f22e90, sym_off: 0x00000034, file: basic_file.cc:260:16
                // warning: not find area, start: 0x7ffd427a2000, end: 0x7ffd427a4000, addr: 0x2567646573257325
                // addr: 0x000000f22ec4 elf: /root/.vscode-server/extensions/ms-vscode.cpptools-1.24.5-linux-x64/bin/cpptools-srv elf_off:   0xb22ec4, sym: std::__basic_file<char>::open(char const*, std::_Ios_Openmode, int), sym_addr: 0x00f22e90, sym_off: 0x00000034, file: basic_file.cc:260:16
                // warning: not find area, start: 0x7ffd9d5e7000, end: 0x7ffd9d5e9000, addr: 0x2567646573257325
                // 有時候會出現很大的 stack address
                std::println(ostream, "warning: not find area, addr: {:#x}, start: {:#x}, end: {:#x}",
                    key.vm_start,
                    find_area->vm_start,
                    find_area->vm_end);
                continue;
            }

            auto elf_off = addr - find_area->vm_start
                                + find_area->vm_pgoff * 4096;

            if (find_area->path == path{})
            {
                std::println(ostream, "    "
                    "elf: anonymous mapping, elf_off: {:>#10x}, addr: {:#x}, start: {:#x}, end: {:#x}",
                    elf_off,
                    addr,
                    find_area->vm_start,
                    find_area->vm_end);
                continue;
            }

            // eBPF 在 path_tailcall 階段，會對首次出現的 path 先在 map 中設置 flag，然後才處理該 path。
            // 而本次 event 的 path_tailcall 會跳過已設 flag 的 path，但該 path 仍可能在其他 event 中處理。  
            // 因此必須等到其他 event 處理完畢並將 path 插入 map 後，再進行查找。
            auto path_iterator = co_await path_handler_.async_find(find_area->path);

            // 理論上不太可能沒有找到，因為如果 path 一直沒有被插入，則會卡在 co_await
            if  (path_iterator == std::end(path_handler_))
            {
                auto path_ktime = path_handler_.ktime(find_area->path);

                std::println(ostream, "    "
                    "elf: not find path, elf_off: {:>#10x}, cpu: {}, latency: {}, "
                    "addr: {:#x}, start: {:#x}, end: {:#x}, mnt: {:p}, dentry: {:p}",
                    elf_off,
                    cpu,
                    static_cast<__s64>(event->ktime - path_ktime),
                    addr,
                    find_area->vm_start,
                    find_area->vm_end,
                    find_area->path.mnt,
                    find_area->path.dentry);
                continue;
            }

            std::print(ostream, "    "
                "elf: {:40} elf_off: {:>#10x}",
                path_iterator->second,
                elf_off);

            blaze_symbolize_src_elf src =
            {
                .type_size  = sizeof(src),
                .path       = std::data(path_iterator->second),
                .debug_syms = true
            };

            auto syms = std::unique_ptr<const blaze_syms, decltype(&blaze_syms_free)>{
                blaze_symbolize_elf_file_offsets(symbolizer_,
                                                 &src,
                                                 &elf_off,
                                                 1),
                blaze_syms_free};

            if (syms)
            {
                const auto& sym = syms->syms[0];
                if (sym.reason)
                    std::print(ostream, ", sym: {}", blaze_symbolize_reason_str(sym.reason));
                else
                {
                    std::print(ostream, ", sym: {}, sym_addr: {:#010x}, sym_off: {:#010x}",
                        sym.name,
                        sym.addr,
                        sym.offset);

                    if (sym.code_info.file)
                        std::print(ostream, ", file: {}:{}:{}",
                            sym.code_info.file,
                            sym.code_info.line,
                            sym.code_info.column);
                }
            }
            else
            {
                std::print(ostream, ", {}", blaze_err_str(blaze_err_last()));
            }

            std::println(ostream);
        }

        co_return;
    }
};

template<std::size_t number>
class event_handler
{
    std::array<std::function<void(int, void*, __u32)>, number> handlers_{};
    std::size_t event_count_ = 0;

    constexpr void handle_event(int cpu, void *data, __u32 size) noexcept
    {
        auto event = static_cast<event_base*>(data);
        if (handlers_[event->event_id])
            handlers_[event->event_id](cpu, data, size);

        event_count_++;
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

    constexpr auto event_count() const noexcept
    {
        return event_count_;
    }

    static constexpr void callback(void* ctx, int cpu, void* data, __u32 size) noexcept
    {
        auto handler = static_cast<event_handler*>(ctx);

        // 呼叫實際的 member function
        handler->handle_event(cpu, data, size);
    }

    static constexpr void lost(void *ctx, int cpu, __u64 cnt) noexcept
    {
        std::println(std::cout, "warning: lost event, cpu: {}, cnt: {}", cpu, cnt);
    }
};

template<typename Container, typename size_type = Container::size_type>
auto set_bit(Container& container, size_type bit)
{
    using value_type = typename Container::value_type;

    auto index  = bit / std::numeric_limits<value_type>::digits;
    auto offset = bit % std::numeric_limits<value_type>::digits;

    container[index] |= value_type{1} << offset;
}

template<typename Container>
auto parse_syscalls(Container &container, std::string_view value)
{
    auto is_name_char = [](auto c)
    {
        // 需先將型別轉換成 unsigned，否則負數在型別提升時，高位元會被補 1
        using unsigned_type = std::make_unsigned_t<decltype(c)>;

        return std::islower(static_cast<unsigned_type>(c)) ||
               std::isdigit(static_cast<unsigned_type>(c)) ||
               c == '_';
    };

    for (auto iterator = std::begin(value); iterator != std::end(value);)
    {
        auto start = std::find_if(iterator, std::end(value), is_name_char);
        if  (start == std::end(value))
            break;
        iterator = std::find_if_not(start, std::end(value), is_name_char);

        if (auto entry = syscall_name_to_nr(&*start, std::distance(start, iterator)))
            set_bit(container, entry->nr);
    }
}

auto env_equal(const char *name, const char *string)
{
    if (auto env_value = getenv(name))
        return strcmp(env_value, string) == 0;

    return false;
}

int main(int argc, char *argv[])
{
    if  (auto env_value = getenv("OUTPUT_FILE"))
    {
        // 關閉同步後，需要使用 stdout 和 stderr 與 C 語言相容
        std::ios::sync_with_stdio(false);

        // 開啟要寫入的檔案（O_WRONLY 為寫入模式，O_CREAT 如果檔案不存在就建立它，O_TRUNC 為清空檔案內容
        int fd = open(env_value, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd < 0)
            throw std::system_error{errno, std::system_category(), "open"};

        if (dup3(fd, STDOUT_FILENO, 0) < 0)
            throw std::system_error{errno, std::system_category(), "dup3"};

        if (dup3(fd, STDERR_FILENO, 0) < 0)
            throw std::system_error{errno, std::system_category(), "dup3"};

        if (close(fd) < 0)
            throw std::system_error{errno, std::system_category(), "close"};
    }

    if (SIG_ERR == std::signal(SIGINT,  signal_handler))
        throw std::system_error{errno, std::system_category(), "std::signal"};

    if (SIG_ERR == std::signal(SIGTERM, signal_handler))
        throw std::system_error{errno, std::system_category(), "std::signal"};

    // open and load eBPF skeleton
    auto skeleton = std::unique_ptr<signal_bpf,        decltype(&signal_bpf::destroy)>{
                                    signal_bpf::open_and_load(), signal_bpf::destroy};
    if (!skeleton)
        throw std::system_error{-errno, std::system_category(), "signal_bpf::open_and_load"};

    const __u32 zero = 0;
    char command_pattern[MAX_ARG_LEN] = "";

    if (auto env_value = getenv("COMMAND_PATTERN"))
    {
        auto result = std::format_to_n(command_pattern, MAX_ARG_LEN, "{}", env_value);
        if  (result.size != MAX_ARG_LEN)
            *result.out = '\0';
    }

    // update pattern to bpf map
    int  error = 0;
    if ((error = bpf_map__update_elem(skeleton->maps.command_pattern,
                                      &zero, sizeof(zero),
                                      command_pattern, sizeof(command_pattern), BPF_ANY)) < 0)
        throw std::system_error{-error, std::system_category(), "bpf_map__update_elem"};

    __u32 read_content = env_equal("READ_CONTENT", "true");

    // update read_content flag to bpf map
    if ((error = bpf_map__update_elem(skeleton->maps.read_content,
                                      &zero, sizeof(zero),
                                      &read_content, sizeof(read_content), BPF_ANY)) < 0)
        throw std::system_error{-error, std::system_category(), "bpf_map__update_elem"};

    struct stat st{};
    if ((error = stat("/proc/self/ns/pid", &st)) < 0)
        throw std::system_error{-error, std::system_category(), "stat"};

    self_t self =
    {
        .pid  = static_cast<__u32>(syscall(SYS_gettid)),
        .tgid = static_cast<__u32>(syscall(SYS_getpid)),
        .dev  = st.st_dev,
        .ino  = st.st_ino
    };

    // update self to bpf map
    if ((error = bpf_map__update_elem(skeleton->maps.self_map,
                                      &zero, sizeof(zero),
                                      &self, sizeof(self), BPF_ANY)) < 0)
        throw std::system_error{-error, std::system_category(), "bpf_map__update_elem"};

    std::array<__u64, MAX_SYSCALL> syscell_success_map{};
    if (auto env_value = getenv("SYSCELL_SUCCESS"))
        parse_syscalls(syscell_success_map, env_value);

    std::array<__u64, MAX_SYSCALL> syscell_fail_map{};
    if (auto env_value = getenv("SYSCELL_FAIL"))
        parse_syscalls(syscell_fail_map, env_value);

    std::array<__u64, MAX_SYSCALL> syscell_stack_map{};
    if (auto env_value = getenv("SYSCELL_STACK"))
        parse_syscalls(syscell_stack_map, env_value);

    // update syscell map to bpf
    if ((error = bpf_map__update_elem(skeleton->maps.syscell_success_map,
                                      &zero, sizeof(zero),
                                      std::data(syscell_success_map), sizeof(syscell_success_map), BPF_ANY)) < 0)
        throw std::system_error{-error, std::system_category(), "bpf_map__update_elem"};

    if ((error = bpf_map__update_elem(skeleton->maps.syscell_fail_map,
                                      &zero, sizeof(zero),
                                      std::data(syscell_fail_map), sizeof(syscell_fail_map), BPF_ANY)) < 0)
        throw std::system_error{-error, std::system_category(), "bpf_map__update_elem"};

    if ((error = bpf_map__update_elem(skeleton->maps.syscell_stack_map,
                                      &zero, sizeof(zero),
                                      std::data(syscell_stack_map), sizeof(syscell_stack_map), BPF_ANY)) < 0)
        throw std::system_error{-error, std::system_category(), "bpf_map__update_elem"};

    constexpr std::string_view build_id_dir{"/usr/lib/debug/.build-id"};

    std::vector<std::string> dirent_names;
    if (auto directory = std::unique_ptr<DIR, decltype(&closedir)>{opendir(std::data(build_id_dir)), closedir})
    {
        errno = 0;
        while (auto dirent = readdir(directory.get()))
        {
            if (dirent->d_type != DT_DIR)
                continue;

            if (dirent->d_name[0] == '.'  &&
               (dirent->d_name[1] == '\0' ||
               (dirent->d_name[1] == '.'  &&
                dirent->d_name[2] == '\0')))
                continue;

            dirent_names.emplace_back(dirent->d_name);
        }

        if (errno)
            throw std::system_error{errno, std::system_category(), "readdir"};
    }
    else if (errno != ENOENT)
        throw std::system_error{errno, std::system_category(), "opendir"};

    std::vector<const char *> debug_dirs(std::size(dirent_names));
    std::ranges::transform(dirent_names, std::begin(debug_dirs), std::mem_fn(&std::string::c_str));

    blaze_symbolizer_opts symbolizer_opts =
    {
        .type_size = sizeof(symbolizer_opts),
        .debug_dirs = std::data(debug_dirs),
        .debug_dirs_len = std::size(debug_dirs),
        // .auto_reload = true, // 可選：若 ELF 檔有變更，自動 reload
        .code_info = true,   // 啟用 DWARF 行號資訊解析
        // .inlined_fns = true, // 可選：還原 inline 函數
        .demangle = true     // 還原 C++ / Rust 函數名稱
    };

    auto symbolizer = std::unique_ptr<blaze_symbolizer, decltype(&blaze_symbolizer_free)>{
        blaze_symbolizer_new_opts(&symbolizer_opts),
        blaze_symbolizer_free};
    if (!symbolizer)
        throw std::runtime_error(blaze_err_str(blaze_err_last()));

    blaze_normalizer_opts normalizer_opts =
    {
        .type_size = sizeof(normalizer_opts),
        .build_ids = true,
        .cache_build_ids = true
    };

    auto normalizer = std::unique_ptr<blaze_normalizer, decltype(&blaze_normalizer_free)>{
        blaze_normalizer_new_opts(&normalizer_opts),
        blaze_normalizer_free};
    if (!normalizer)
        throw std::runtime_error(blaze_err_str(blaze_err_last()));

    std::unordered_map<__u64, std::osyncstream> osyncstream_map;

    path_event_handler   path_handler{ .bpf_path_map_ = skeleton->maps.path_map };

    execve_event_handler execve_handler;
    kill_event_handler   kill_handler;
    read_event_handler   read_handler{ .path_handler_ = path_handler, .context = read_content };
    std::unordered_map<__u64, std::set<vm_area_event::vm_area, vm_area_comp>> vm_area_map;

    event_handler<EVENT_MAX> handler;
    handler[EVENT_ID(sys_enter_execve_event)]   = std::bind_front(&execve_event_handler::enter, &execve_handler);
    handler[EVENT_ID(sys_exit_execve_event)]    = std::bind_front(&execve_event_handler::exit,  &execve_handler);
    handler[EVENT_ID(sys_enter_kill_event)]     = std::bind_front(&kill_event_handler::enter,   &kill_handler);
    handler[EVENT_ID(sys_exit_kill_event)]      = std::bind_front(&kill_event_handler::exit,    &kill_handler);
    handler[EVENT_ID(sys_enter_read_event)]     = std::bind_front(&read_event_handler::enter,   &read_handler);
    handler[EVENT_ID(sys_exit_read_event)]      = std::bind_front(&read_event_handler::exit,    &read_handler);
    handler[EVENT_ID(path_event)]               = std::ref(path_handler);
    handler[EVENT_ID(vm_area_event)]            = vm_area_handler{vm_area_map, false, false, 32};
    handler[EVENT_ID(stack_event)]              = stack_handler{normalizer.get(), symbolizer.get(), vm_area_map, path_handler, osyncstream_map };
    handler[EVENT_ID(sched_process_exit_event)] = handle_sched_process_exit;
    handler[EVENT_ID(do_coredump_event)]        = do_coredump_handler{osyncstream_map};
    handler[EVENT_ID(sys_exit_event)]           = exit_event_handler{osyncstream_map};
    handler[EVENT_ID(do_mmap_event)]            = do_mmap_handler{vm_area_map};

    // perf buffer 選項
    perf_buffer_opts pb_opts{ .sz = sizeof(perf_buffer_opts) };

    // 建立 perf buffer
    auto perf_buffer_ptr = std::unique_ptr<perf_buffer, decltype(&perf_buffer__free)>{
         perf_buffer__new(bpf_map__fd(skeleton->maps.events),
                          512,
                          handler.callback,
                          handler.lost,
                          &handler,
                          &pb_opts),
         perf_buffer__free};
    if (!perf_buffer_ptr)
        throw std::system_error{-errno, std::system_category(), "perf_buffer__new"};

    bool attach_execve = env_equal("ATTACH_EXECVE", "true");
    bpf_program__set_autoattach(skeleton->progs.tracepoint__syscalls__sys_enter_execve, attach_execve);
    bpf_program__set_autoattach(skeleton->progs.tracepoint__syscalls__sys_exit_execve,  attach_execve);

    bool process_exit_execve = env_equal("ATTACH_PROCESS_EXIT", "true");
    bpf_program__set_autoattach(skeleton->progs.tracepoint__sched__sched_process_exit, process_exit_execve);

    bool attach_read = env_equal("ATTACH_READ", "true");
    bpf_program__set_autoattach(skeleton->progs.tracepoint__syscalls__sys_enter_read, attach_read);
    bpf_program__set_autoattach(skeleton->progs.tracepoint__syscalls__sys_exit_read,  attach_read);

    bool attach_mmap = env_equal("ATTACH_MMAP", "true");
    bpf_program__set_autoattach(skeleton->progs.kprobe__do_mmap,    attach_mmap);
    bpf_program__set_autoattach(skeleton->progs.kretprobe__do_mmap, attach_mmap);

    // attach eBPF 程式到對應的 tracepoint
    if ((error = signal_bpf::attach(skeleton.get())) < 0)
        throw std::system_error{-error, std::system_category(), "signal_bpf::attach"};

    std::println(std::cout, "Successfully started! Ctrl+C to stop.");

    auto next_time = std::chrono::system_clock::now();

    // 進入 poll loop
    while (!g_signal_status)
    {
        auto count = perf_buffer__poll(perf_buffer_ptr.get(), 100 /* ms */);
        if  (count < 0 && count != -EINTR)
            throw std::system_error{-count, std::system_category(), "perf_buffer__poll"};

        auto time = std::chrono::system_clock::now();
        if  (time > next_time)
        {
            std::println(std::cout, "time: {}, handled event: {}", time, handler.event_count());
            next_time += std::chrono::seconds{1};
        }
    }

    std::println(std::cout, "Stopped. Exiting normally.");
    return 0;
}
