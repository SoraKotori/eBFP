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

#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>

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
    //     std::println("blaze_normalize_user_addrs_opts: {}", blaze_err_str(blaze_err_last()));
    //     return;
    // }

    // for (std::size_t i = 0; i < std::size(addrs); i++)
    // {
    //     const auto& meta = output->metas[output->outputs[i].meta_idx];

    //     if      (meta.kind == blaze_user_meta_kind::BLAZE_USER_META_UNKNOWN)
    //     {
    //         std::println("    {:>2}, abs_addr: {:>#18x}, {}",
    //             i, addrs[i],
    //             blaze_normalize_reason_str(meta.variant.unknown.reason));
    //     }
    //     else if (meta.kind == blaze_user_meta_kind::BLAZE_USER_META_APK)
    //     {
    //         std::println("    {:>2}, abs_addr: {:>#18x}, apk: {:40} apk_off: {:>#10x}",
    //             i, addrs[i],
    //             std::format("\"{}\"", meta.variant.apk.path),
    //             output->outputs[i].output);
    //     }
    //     else if (meta.kind == blaze_user_meta_kind::BLAZE_USER_META_ELF)
    //     {
    //         std::print("    {:>2}, abs_addr: {:>#18x}, elf: {:40} elf_off: {:>#10x}",
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
    //                 std::print(", \"{}\"", blaze_symbolize_reason_str(sym.reason));
    //             else
    //             {
    //                 std::print(", sym: {}, sym_addr: {:#010x}, sym_off: {:#010x}",
    //                     sym.name,
    //                     sym.addr,
    //                     sym.offset);

    //                 if (sym.code_info.file)
    //                     std::print(", file: {}:{}:{}",
    //                         sym.code_info.file,
    //                         sym.code_info.line,
    //                         sym.code_info.column);
    //             }
    //         }
    //         else
    //         {
    //             std::print(", {}", blaze_err_str(blaze_err_last()));
    //         }

    //         std::println();
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
        std::println("blaze_symbolize_process_abs_addrs: {}", blaze_err_str(blaze_err_last()));

        for(std::size_t i = 0; i < std::size(addrs); i++)
            std::println("    #{:<2} {:#014x}", i, addrs[i]);

        return;
    }

    // sudo eBFP/blazesym/target/debug/blazecli symbolize process --pid 259062 0x005642ad65d095
    // 0x005642ad65d095: _start @ 0x1070+0x25

    for(std::size_t i = 0; i < std::size(addrs); i++)
    {
        std::print("    #{:<2} {:#014x} in {:<20}",
            i, addrs[i],
            syms->syms[i].name ? syms->syms[i].name : "null");

        if (syms->syms[i].reason)
            std::println(" {}", blaze_symbolize_reason_str(syms->syms[i].reason));
        else
            std::println(" sym_addr: {:#014x}, sym_off: {:#010x}, name: {}:{}:{}",
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

    auto println(__u32 tgid, __u32 pid, int cpu)
    {
        std::println("pid: {:>6}, tid: {:>6}, execve, cpu: {}, ret: {:>5}, argc: {}, argv: {}",
                     tgid, pid, cpu, ret.value(), argc.value(), argv);
        
        if (argc.value() == MAX_ARGV_UNROLL)
            std::println("warning: execve argv count reached limit ({}), possible truncation", MAX_ARGV_UNROLL);
    }
};

struct sys_enter_execve_handler
{
    std::unordered_map<__u64, execve_argument>& map_;

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_enter_execve_event*>(data);

        auto& argument = map_[event->ktime];

        if (event->argv_i_size)
        {
            if (event->i == std::size(argument.argv))
                argument.argv.emplace_back(event->argv_i, event->argv_i_size - 1); // not include '\0'
            else
                std::println("pid: {:>6}, tid: {:>6}, execve, cpu: {}, warning: out of order",
                             event->tgid, event->pid, cpu);
        }
        else
        {
            argument.argc = event->i;
            if (argument.ret)
                argument.println(event->tgid, event->pid, cpu);
        }
    }
};

struct sys_exit_execve_handler
{
    std::unordered_map<__u64, execve_argument>& map_;

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_exit_execve_event*>(data);

        auto& argument = map_[event->ktime];
        argument.ret = event->ret;

        if (argument.argc)
            argument.println(event->tgid, event->pid, cpu);
    }
};

struct kill_argument
{
    std::optional<long> ret;
    __u32               target_pid;
    std::optional<int>  signal;

    auto println(__u32 tgid, __u32 pid, int cpu)
    {
        std::println("pid: {:>6}, tid: {:>6}, kill,    ret: {:>5}, target pid: {}, signal: {}",
            tgid,
            pid,
            ret.value(),
            target_pid,
            signal.value());
    }
};

struct sys_enter_kill_handler
{
    std::unordered_map<__u64, kill_argument>& map_;

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_enter_kill_event*>(data);

        auto& argument = map_[event->ktime];
        argument.target_pid = event->target_pid;
        argument.signal     = event->signal;

        if (argument.ret)
            argument.println(event->tgid, event->pid, cpu);
    }
};

struct sys_exit_kill_handler
{
    std::unordered_map<__u64, kill_argument>& map_;

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_exit_kill_event*>(data);

        auto& argument = map_[event->ktime];
        argument.ret = event->ret;

        if (argument.signal)
            argument.println(event->tgid, event->pid, cpu);
    }
};

// read_argument: 用於蒐集同一次 read() 呼叫的參數與緩衝區內容
// 在同一個 eBPF 程式中，sys_exit_read 會先送出回傳值 (buffer 大小)
// 接著 sys_enter_read 再負責將實際讀取的內容填入 buffer
struct read_argument
{
    long ret;
    int fd;
    __u16 i_mode;
    struct path path;
    std::vector<char> buffer;

    // 定義最大長度，eBPF 最大可傳送的大小
    static constexpr long max_size = MAX_READ_UNROLL * MAX_ARG_LEN;

    template<typename Char>
    auto println(__u32 tgid, __u32 pid, int cpu, std::basic_string_view<Char> path_name)
    {     
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

        std::println("pid: {:>6}, tid: {:>6}, read,    ret: {:>5}, fd: {:>3}, {} ({}), name: \"{}\"",
                     tgid, pid, ret, fd, permission, mode, path_name);

        // 如果 read size 超出上限，就截斷並印出警告
        if (ret > max_size)
            std::println("warning: read size {} exceeds limit {}, truncating to {}",
                         ret, max_size, max_size);

        // 若有讀取到資料，並且不是 ELF 檔，則輸出文字內容
        if (ret > 0)
        {
            constexpr std::string_view magic{"\177ELF"};

            if (std::end(magic) != std::ranges::mismatch(buffer, magic).in2)
                std::println("{}", std::string_view{std::begin(buffer), std::end(buffer)});
        }
    }
};

struct sys_enter_read_handler
{
    std::unordered_map<__u64, read_argument>& map_;
    const std::unordered_map<path, std::string, path_hash>& names_map_;

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_enter_read_event*>(data);

        // 根據 ktime 找到對應的 read_argument
        auto iterator = map_.find(event->ktime);
        if  (iterator == std::end(map_))
        {
            // sys_exit_read 與 sys_enter_read 在相同的 eBPF 程式中，
            // 理論上不應該有 out-of-order 的情況
            std::println("warning: read_argument not found for ktime {}", event->ktime);
            return;
        }

        auto& argument = iterator->second;
        auto  buffer_begin = std::begin(argument.buffer) + event->index;
        auto  buffer_end   = std::end  (argument.buffer);

        // 將本次讀取的資料片段複製到 buffer
        // 如果 copy_n 回傳 buffer_end，代表已經接收完整 content
        if (buffer_end == std::copy_n(event->buf, event->size, buffer_begin))
        {
            // path_event 可能尚未到達，導致 names_map_ 查不到路徑名稱
            auto find_path = names_map_.find(argument.path);
            auto path_name = find_path == std::end(names_map_) ? std::string_view{"not find path"}
                                                               : std::string_view{find_path->second};

            argument.println(event->tgid, event->pid, cpu, path_name);
            map_.erase(iterator);
        }
    }
};

struct sys_exit_read_handler
{
    std::unordered_map<__u64, read_argument>& map_;
    const std::unordered_map<path, std::string, path_hash>& names_map_;

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_exit_read_event*>(data);

        // 以 ktime 作為 key 建立新的 read_argument
        auto [iterator, inserted] = map_.try_emplace(event->ktime, event->ret,
                                                                   event->fd,
                                                                   event->i_mode,
                                                                   event->path);
        if (!inserted)
        {
            // ktime 重複的情況理論上不應該發生
            std::println("warning: failed to insert read_argument for ktime {}", event->ktime);
            return;
        }

        auto& argument = iterator->second;

        // 根據回傳值調整 buffer 大小; 若 ret <= 0，立刻輸出並移除
        if (event->ret > 0)
        {
            // 如果 event->ret 超出上限，就截斷
            argument.buffer.resize(std::min(event->ret, argument.max_size));
        }
        else
        {
            // event 可能 out-of-order 到達，若 path_event 尚未抵達，則找不到 path name
            auto find_path = names_map_.find(event->path);
            auto path_name = find_path == std::end(names_map_) ? std::string_view{"not find path"}
                                                               : std::string_view{find_path->second};

            argument.println(event->tgid, event->pid, cpu, path_name);
            map_.erase(iterator);
        }
    }
};

struct path_handler
{
    std::unordered_map<path, std::string, path_hash>& names_map_;

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<path_event*>(data);

        std::string_view path_name{
            event->name + event->index,
            event->name + MAX_ARG_LEN - MAX_NAME_LEN};

        auto [iterator, inserted] = names_map_.try_emplace(event->path, std::move(path_name));

        if (inserted)
        {
            struct timespec tp{};
            if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0)
            {
                std::system_error error{errno, std::system_category()};
                std::println("warning: clock_gettime, code: {}, what: {}", error.code().value(),
                                                                           error.what());
            }
            else
            {
                std::println("    cpu: {}, path: {}, ktime: {}, mnt: {:p}, dentry: {:p}",
                             cpu,
                             iterator->second,
                             tp.tv_sec * 1'000'000'000 + tp.tv_nsec - event->ktime,
                             event->path.mnt,
                             event->path.dentry);
            }
        }
        else
        {
            std::println("warning: names_map_.try_emplace.inserted == false\n"
                         "    old path: {}\n"
                         "    new path: {}", iterator->second, path_name);
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

    // 若能得知 cpu 數量，可以改用 std::array
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
            std::println("pid: {:>6}, tid: {:>6}, vm_area, cpu: {}, size: {}",
                         event->tgid,
                         event->pid,
                         cpu,
                         std::size(areas));

        if (print_area_)
            for (const auto& entry : areas)
                std::println("    start: {:#x}, end: {:#x}, pgoff: {:#x}, mnt: {:p}, dentry: {:p}",
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

    std::print("pid: {:>6}, tid: {:>6}, ",
        event->tgid, // pid
        event->pid); // tid

    auto status = event->exit_code;

    if (WIFEXITED(status))
        std::println("exited,  ret: {:>5}", WEXITSTATUS(status));

    else if (WIFSIGNALED(status))
        std::println("killed,  ret: {:>5} SIG{} ({}){}",
            WTERMSIG(status),
            sigabbrev_np(WTERMSIG(status)) ? sigabbrev_np(WTERMSIG(status)) : "null",
            sigdescr_np (WTERMSIG(status)) ? sigdescr_np (WTERMSIG(status)) : "null",
            WCOREDUMP(status) ? ", (core dumped)" : ""); // 判斷是否發生 Core Dump
}

class do_coredump_handler
{
public:
    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<do_coredump_event*>(data);
    }
};

class sys_exit_handler
{
public:
    void operator()(int cpu, void *data, __u32 size) const
    {
        auto event = static_cast<sys_exit_event*>(data);

        std::println("pid: {:>6}, tid: {:>6}, syscall, cpu: {}, ret: {:>5}, number: {}",
            event->tgid,
            event->pid,
            cpu,
            event->ret,
            event->syscall_nr);
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

class do_mmap_handler
{
    std::unordered_map<__u64, std::set<vm_area_event::vm_area, vm_area_comp>>& vm_area_map_;

public:
    do_mmap_handler(decltype(vm_area_map_) vm_area_map) :
        vm_area_map_{vm_area_map}
    {}

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

        // std::println("    "
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

class stack_handler
{
    blaze_normalizer* normalizer_;
    blaze_symbolizer* symbolizer_;
    const std::unordered_map<__u64, std::set<vm_area_event::vm_area, vm_area_comp>>& vm_area_map_;
    const std::unordered_map<path,  std::string, path_hash>& names_map_;
    bpf_map *path_map_;

public:
    stack_handler(blaze_normalizer* normalizer,
                  blaze_symbolizer* symbolizer,
                  decltype(vm_area_map_) vm_area_map,
                  decltype(names_map_) names_map,
                  bpf_map *path_map) :
        normalizer_{normalizer},
        symbolizer_{symbolizer},
        vm_area_map_{vm_area_map},
        names_map_{names_map},
        path_map_{path_map}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<stack_event*>(data);

        const auto& areas = vm_area_map_.at(event->pid_tgid);
        const auto  addrs = std::span<unsigned long>{event->addrs, event->addr_size};
        // print_stack_trace(normalizer_, symbolizer_, event->tgid, addrs);

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
                std::println("warning: not find area, addr: {:#x}, start: {:#x}, end: {:#x}",
                    key.vm_start,
                    find_area->vm_start,
                    find_area->vm_end);
                continue;
            }

            auto elf_off = addr - find_area->vm_start
                                + find_area->vm_pgoff * 4096;

            if (find_area->path == path{})
            {
                std::println("    elf: anonymous mapping, "
                             "elf_off: {:>#10x}, "
                             "addr: {:#x}, start: {:#x}, end: {:#x}",
                             elf_off,
                             addr,
                             find_area->vm_start,
                             find_area->vm_end);
                continue;
            }

            auto find_path = names_map_.find(find_area->path);
            if  (find_path == std::end(names_map_))
            {
                // 因為前面的 eBPF 還在執行 vm_area_tailcall 和 path_tailcall，因為遇到許多第一次的 path
                // 而後面的 eBPF 因為前面的 eBPF 已經標記了 path，所以直接認為 path 已經存在，所以先執行完畢
                // 而實際上要輸出時，第一次的 path 還在處理，導致找不到 path

                __u64 path_ktime = 0;
                if (auto error = bpf_map__lookup_elem(path_map_,
                                                      &find_area->path, sizeof(find_area->path),
                                                      &path_ktime, sizeof(path_ktime), 0))
                {
                    std::system_error system_error{-error, std::system_category()};
                    std::println("    elf: bpf_map__lookup_elem failed, code: {}, what: {}",
                                 system_error.code().value(),
                                 system_error.what());
                    continue;
                }

                std::println("    elf: not find path, elf_off: {:>#10x}, "
                             "cpu: {}, ktime: {}, "
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

            std::print("    elf: {:40} elf_off: {:>#10x}",
                find_path->second,
                elf_off);

            blaze_symbolize_src_elf src =
            {
                .type_size  = sizeof(src),
                .path       = std::data(find_path->second),
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
                    std::print(", sym: {}", blaze_symbolize_reason_str(sym.reason));
                else
                {
                    std::print(", sym: {}, sym_addr: {:#010x}, sym_off: {:#010x}",
                        sym.name,
                        sym.addr,
                        sym.offset);

                    if (sym.code_info.file)
                        std::print(", file: {}:{}:{}",
                            sym.code_info.file,
                            sym.code_info.line,
                            sym.code_info.column);
                }
            }
            else
            {
                std::print(", {}", blaze_err_str(blaze_err_last()));
            }

            std::println();
        }
    }
};

template<std::size_t number>
class event_handler
{
    std::array<std::function<void(int, void*, __u32)>, number> handlers_{};

    constexpr void handle_event(int cpu, void *data, __u32 size) const noexcept
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

    static constexpr void callback(void* ctx, int cpu, void* data, __u32 size) noexcept
    {
        auto handler = static_cast<event_handler*>(ctx);

        // 呼叫實際的 member function
        handler->handle_event(cpu, data, size);
    }

    static constexpr void lost(void *ctx, int cpu, __u64 cnt) noexcept
    {
        std::println("warning: lost event, cpu: {}, cnt: {}", cpu, cnt);
    }
};

template<typename Container, typename size_type = Container::size_type>
auto set_ret(Container& container, size_type bit)
{
    using value_type = typename Container::value_type;

    return container[bit / (sizeof(value_type) * 8)] |= 1 << bit % (sizeof(value_type) * 8);
}

int main(int argc, char *argv[])
{
    bool redirect = argc > 1;
    if  (redirect)
    {
        // 關閉同步後，需要使用 stdout 和 stderr 與 C 語言相容
        std::ios::sync_with_stdio(false);

        // 開啟要寫入的檔案（O_WRONLY 為寫入模式，O_CREAT 如果檔案不存在就建立它，O_TRUNC 為清空檔案內容
        int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd < 0)
            throw std::system_error{errno, std::system_category()};

        if (dup3(fd, STDOUT_FILENO, 0) < 0)
            throw std::system_error{errno, std::system_category()};

        if (dup3(fd, STDERR_FILENO, 0) < 0)
            throw std::system_error{errno, std::system_category()};

        if (close(fd) < 0)
            throw std::system_error{errno, std::system_category()};
    }

    if (SIG_ERR == std::signal(SIGINT,  signal_handler))
        throw std::system_error{errno, std::system_category()};

    if (SIG_ERR == std::signal(SIGTERM, signal_handler))
        throw std::system_error{errno, std::system_category()};

    // open and load eBPF skeleton
    auto skeleton = std::unique_ptr<signal_bpf,        decltype(&signal_bpf::destroy)>{
                                    signal_bpf::open_and_load(), signal_bpf::destroy};
    if (!skeleton)
        throw std::system_error{-errno, std::system_category()};

    const __u32 zero = 0;
    char pattern[MAX_ARG_LEN] = "";

    // update pattern to bpf map
    int  error = 0;
    if ((error = bpf_map__update_elem(skeleton->maps.command_pattern,
                                      &zero, sizeof(zero),
                                      pattern, sizeof(pattern), BPF_ANY)) < 0)
        throw std::system_error{-error, std::system_category()};

    // update read_content flag to bpf map
    __u32 context = false;
    if ((error = bpf_map__update_elem(skeleton->maps.read_content,
                                      &zero, sizeof(zero),
                                      &context, sizeof(context), BPF_ANY)) < 0)
        throw std::system_error{-error, std::system_category()};

    struct stat st{};
    if ((error = stat("/proc/self/ns/pid", &st)) < 0)
        throw std::system_error{-error, std::system_category()};

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
        throw std::system_error{-error, std::system_category()};

    std::array<__u64, MAX_SYSCALL> negative_ret{};
    set_ret(negative_ret, SYS_open);
    set_ret(negative_ret, SYS_openat);
    set_ret(negative_ret, SYS_openat2);

    // update negative_ret to bpf map
    if ((error = bpf_map__update_elem(skeleton->maps.negative_ret_map,
                                      &zero, sizeof(zero),
                                      std::data(negative_ret), sizeof(negative_ret), BPF_ANY)) < 0)
        throw std::system_error{-error, std::system_category()};

    const char *debug_dirs[] = { "/usr/lib/debug",
                                 "/lib/debug",
                                 "/usr/lib/debug/.build-id/46",
                                 "/usr/lib/debug/.build-id/48",
                                 "/usr/lib/debug/.build-id/6a",
                                 "/workspaces/eBFP" };

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

    std::unordered_map<__u64, execve_argument> execve_map;
    std::unordered_map<__u64, kill_argument> kill_map;
    std::unordered_map<__u64, read_argument> read_map;
    std::unordered_map<__u64, std::set<vm_area_event::vm_area, vm_area_comp>> vm_area_map;
    std::unordered_map<path,  std::string, path_hash> names_map;

    event_handler<EVENT_MAX> handler;
    handler[EVENT_ID(sys_enter_execve_event)]   = sys_enter_execve_handler{execve_map};
    handler[EVENT_ID(sys_exit_execve_event)]    = sys_exit_execve_handler{execve_map};
    handler[EVENT_ID(sys_enter_kill_event)]     = sys_enter_kill_handler{kill_map};
    handler[EVENT_ID(sys_exit_kill_event)]      = sys_exit_kill_handler{kill_map};
    handler[EVENT_ID(sys_enter_read_event)]     = sys_enter_read_handler{read_map, names_map};
    handler[EVENT_ID(sys_exit_read_event)]      = sys_exit_read_handler{read_map, names_map};
    handler[EVENT_ID(path_event)]               = path_handler{names_map};
    handler[EVENT_ID(vm_area_event)]            = vm_area_handler{vm_area_map, true, true, 32};
    handler[EVENT_ID(stack_event)]              = stack_handler{normalizer.get(), symbolizer.get(), vm_area_map, names_map, skeleton->maps.path_map};
    handler[EVENT_ID(sched_process_exit_event)] = handle_sched_process_exit;
    handler[EVENT_ID(do_coredump_event)]        = do_coredump_handler{};
    handler[EVENT_ID(sys_exit_event)]           = sys_exit_handler{};
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
        throw std::system_error{-errno, std::system_category(), "Failed to create perf buffer"};

    bool attach_read = true;
    bpf_program__set_autoattach(skeleton->progs.tracepoint__syscalls__sys_enter_read, attach_read);
    bpf_program__set_autoattach(skeleton->progs.tracepoint__syscalls__sys_exit_read,  attach_read);

    bool attach_mmap = false;
    bpf_program__set_autoattach(skeleton->progs.kprobe__do_mmap,    attach_mmap);
    bpf_program__set_autoattach(skeleton->progs.kretprobe__do_mmap, attach_mmap);

    // attach eBPF 程式到對應的 tracepoint
    if ((error = signal_bpf::attach(skeleton.get())) < 0)
        throw std::system_error{-error, std::system_category()};

    std::println("Successfully started! Ctrl+C to stop.");

    // 進入 poll loop
    while (!g_signal_status)
    {
        if ((error = perf_buffer__poll(perf_buffer_ptr.get(), 100 /* ms */)) < 0 &&
             error != -EINTR)
            throw std::system_error{-error, std::system_category(), "Error polling perf buffer"};
    }

    std::println("Stopped. Exiting normally.");
    return 0;
}
