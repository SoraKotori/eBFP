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
    std::optional<long> ret;
    std::optional<__u32> argc;
    std::vector<std::string> argv;

    auto println(__u32 tgid, __u32 pid, int cpu)
    {
        std::println("pid: {:>6}, tid: {:>6}, execve, cpu: {}, ret: {:>5}, argc: {}, argv: {}",
            tgid,
            pid,
            cpu,
            ret.value(),
            argc.value(),
            argv);
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
    __u32 target_pid;
    std::optional<int> signal;

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

using read_argument = std::vector<char>;

class sys_enter_read_handler
{
    std::unordered_map<__u64, read_argument>& map_;

public:
    sys_enter_read_handler(decltype(map_) map) :
        map_{map}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_enter_read_event*>(data);

        auto& content = map_[event->pid_tgid];

        // 仍未傳送完整的 content
        if (std::end(content) != std::copy_n(event->buf, event->size, std::begin(content) + event->index))
            return;

        constexpr std::string_view magic{"\177ELF"};

        // 檢查是否為 ELF 檔，如果非 ELF 則輸出內容
        if (std::end(magic) != std::ranges::mismatch(content, magic).in2)
            std::println("{}", std::string_view{std::begin(content), std::end(content)});
    }
};

class sys_exit_read_handler
{
    std::unordered_map<__u64, read_argument>& map_;
    const std::unordered_map<path, std::string, path_hash>& names_map_;

public:
    sys_exit_read_handler(decltype(map_) map, decltype(names_map_) names_map) :
        map_{map},
        names_map_{names_map}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_exit_read_event*>(data);

        std::string_view mode;
        std::string permission(10, '-');

        if      (S_ISREG (event->i_mode)) { mode = "regular file";     permission[0] = '-'; }
        else if (S_ISDIR (event->i_mode)) { mode = "directory";        permission[0] = 'd'; }
        else if (S_ISCHR (event->i_mode)) { mode = "character device"; permission[0] = 'c'; }
        else if (S_ISBLK (event->i_mode)) { mode = "block device";     permission[0] = 'b'; }
        else if (S_ISFIFO(event->i_mode)) { mode = "FIFO/pipe";        permission[0] = 'p'; }
        else if (S_ISLNK (event->i_mode)) { mode = "symbolic link";    permission[0] = 'l'; }
        else if (S_ISSOCK(event->i_mode)) { mode = "socket";           permission[0] = 's'; }
        else                              { mode = "unknown";          permission[0] = '?'; }

        if (S_IRUSR & event->i_mode) permission[1] = 'r';
        if (S_IWUSR & event->i_mode) permission[2] = 'w';
        if (S_IXUSR & event->i_mode) permission[3] = 'x';
        if (S_IRGRP & event->i_mode) permission[4] = 'r';
        if (S_IWGRP & event->i_mode) permission[5] = 'w';
        if (S_IXGRP & event->i_mode) permission[6] = 'x';
        if (S_IROTH & event->i_mode) permission[7] = 'r';
        if (S_IWOTH & event->i_mode) permission[8] = 'w';
        if (S_IXOTH & event->i_mode) permission[9] = 'x';

        if (S_ISUID & event->i_mode) permission[3] = (event->i_mode & S_IXUSR) ? 's' : 'S';
        if (S_ISGID & event->i_mode) permission[6] = (event->i_mode & S_IXGRP) ? 's' : 'S';
        if (S_ISVTX & event->i_mode) permission[9] = (event->i_mode & S_IXOTH) ? 't' : 'T';

        // event 可能 out-of-order 到達，若 path_event 尚未抵達，則找不到 path name
        auto find_path = names_map_.find(event->path);
        auto path_name = find_path == std::end(names_map_) ? std::string_view{"not find path"}
                                                           : std::string_view{find_path->second};

        std::println("pid: {:>6}, tid: {:>6}, read,    ret: {:>5}, fd: {:>3}, {} ({}), name: \"{}\"",
            event->tgid, // pid
            event->pid,  // tid
            event->ret,
            event->fd,
            permission,
            mode,
            path_name);

        if (event->ret >= 0)
        {
            map_[event->pid_tgid].resize(event->ret);
        }
    }
};

class path_handler
{
    std::unordered_map<path, std::string, path_hash>& names_map_;
    bpf_map *path_map_;

public:
    path_handler(decltype(names_map_) names_map,
                 decltype(path_map_)  path_map) :
        names_map_{names_map},
        path_map_{path_map}
    {}

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
    auto operator()(const vm_area_event::vm_area& left, const vm_area_event::vm_area& right) const
    {
        return left.vm_start < right.vm_start;
    };
};

class vm_area_handler
{
    std::unordered_map<__u64, std::set<vm_area_event::vm_area, vm_area_comp>>& vm_area_map_;
    std::unordered_map<path,  std::string, path_hash>& names_map_;
    std::unordered_map<int, __u64> ktime_map_;

public:
    vm_area_handler(decltype(vm_area_map_) vm_area_map, decltype(names_map_) names_map) :
        vm_area_map_{vm_area_map},
        names_map_{names_map}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<vm_area_event*>(data);

        auto& areas = vm_area_map_[event->pid_tgid];

        if (auto& ktime = ktime_map_[cpu];
            ktime != event->ktime)
        {
            ktime  = event->ktime;
            areas.clear();
        }

        for (auto& area : std::span{event->area, event->area_size})
        {
            areas.emplace_hint(std::end(areas), area);
        }

        if (event->area_size != MAX_AREA)
        {
            std::println("pid: {:>6}, tid: {:>6}, vm_area, cpu: {}, size: {}",
                event->tgid,
                event->pid,
                cpu,
                areas.size());

            // for (const auto& entry : areas)
            // {
            //     auto find = names_map_.find(entry.path);

            //     std::println("    {:#014x} {:#014x} {:#010x} {:p} {:p} name: {}",
            //     entry.vm_start,
            //     entry.vm_end,
            //     entry.vm_pgoff * 4096,
            //     entry.path.dentry,
            //     entry.path.mnt,
            //     find == std::end(names_map_) ? std::string_view{} : find->second);
            // }
        }
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

            auto elf_off = addr - find_area->vm_start + find_area->vm_pgoff * 4096;

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
    __u32 context = true;
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
    handler[EVENT_ID(sys_enter_read_event)]     = sys_enter_read_handler{read_map};
    handler[EVENT_ID(sys_exit_read_event)]      = sys_exit_read_handler{read_map, names_map};
    handler[EVENT_ID(path_event)]               = path_handler{names_map, skeleton->maps.path_map};
    handler[EVENT_ID(vm_area_event)]            = vm_area_handler{vm_area_map, names_map};
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

    bool attach_read = false;
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
