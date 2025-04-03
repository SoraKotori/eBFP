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

#include <sys/wait.h>
#include <sys/stat.h>

#include <bpf/libbpf.h>
#include <blazesym.h>

struct path
{
	void *mnt;
	void *dentry;
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

struct path_equal
{
    bool operator()(const path& left, const path& right) const
    {
        return left.dentry == right.dentry &&
               left.mnt    == right.mnt;
    }
};

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

template<typename T, std::size_t Extent = std::dynamic_extent>
void print_stack_trace(blaze_normalizer* normalizer,
                       blaze_symbolizer* symbolizer,
                       uint32_t tgid,
                       std::span<T, Extent> addrs)
{
    blaze_normalize_opts opts =
    {
        .type_size = sizeof(opts)
    };

    auto output = std::unique_ptr<blaze_normalized_user_output, decltype(&blaze_user_output_free)>{
        blaze_normalize_user_addrs_opts(normalizer,
                                        tgid,
                                        reinterpret_cast<uint64_t*>(std::data(addrs)),
                                        std::size(addrs),
                                        &opts),
        blaze_user_output_free};
    if (!output)
    {
        std::println("blaze_normalize_user_addrs_opts: {}", blaze_err_str(blaze_err_last()));
        return;
    }
        
    for (std::size_t i = 0; i < std::size(addrs); i++)
    {
        const auto& meta = output->metas[output->outputs[i].meta_idx];

        if      (meta.kind == blaze_user_meta_kind::BLAZE_USER_META_UNKNOWN)
        {
            std::print("    {:>2}, abs_addr: {:>#18x}, {}",
                i, addrs[i],
                blaze_normalize_reason_str(meta.variant.unknown.reason));
        }
        else if (meta.kind == blaze_user_meta_kind::BLAZE_USER_META_APK)
        {
            std::print("    {:>2}, abs_addr: {:>#18x}, apk: {:40} apk_off: {:>#10x}",
                i, addrs[i],
                std::format("\"{}\"", meta.variant.apk.path),
                output->outputs[i].output);
        }
        else if (meta.kind == blaze_user_meta_kind::BLAZE_USER_META_ELF)
        {
            std::print("    {:>2}, abs_addr: {:>#18x}, elf: {:40} elf_off: {:>#10x}",
                i, addrs[i],
                std::format("\"{}\"", meta.variant.elf.path),
                output->outputs[i].output);

            // struct bpf_stack_build_id id_off;

            blaze_symbolize_src_elf src =
            {
                .type_size  = sizeof(src),
                .path       = meta.variant.elf.path,
                .debug_syms = true
            };

            auto syms = std::unique_ptr<const blaze_syms, decltype(&blaze_syms_free)>{
                blaze_symbolize_elf_file_offsets(symbolizer,
                                                 &src,
                                                 &output->outputs[i].output,
                                                 1),
                blaze_syms_free};

            if (syms)
            {
                const auto& sym = syms->syms[0];
                if (sym.reason)
                    std::print(", \"{}\"", blaze_symbolize_reason_str(sym.reason));
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
            
            if (meta.variant.elf.build_id_len)
            {
                std::print(", build_id: ");
                for (auto byte : std::span(meta.variant.elf.build_id,
                                           meta.variant.elf.build_id_len))
                    std::print("{:02X}", byte);
            }

            std::println();
        }
    }

    // blaze_symbolize_src_process src =
    // {
    //     .type_size = sizeof(src),
    //     .pid = tgid,
    //     .debug_syms = true,
    //     // .perf_map  = true
    //     // .map_files = true
    // };

    // static_assert(sizeof(uint64_t) == sizeof(typename std::remove_cvref_t<decltype(addrs)>::value_type));

    // auto syms = std::unique_ptr<const blaze_syms, decltype(&blaze_syms_free)>{
    //     blaze_symbolize_process_abs_addrs(symbolizer,
    //                                       &src,
    //                                       reinterpret_cast<uint64_t*>(std::data(addrs)),
    //                                       std::size(addrs)),
    //     blaze_syms_free};
    // if (!syms)
    // {
    //     std::println("blaze_symbolize_process_abs_addrs: {}", blaze_err_str(blaze_err_last()));

    //     for(std::size_t i = 0; i < std::size(addrs); i++)
    //         std::println("    #{:<2} {:#018x}", i, addrs[i]);

    //     return;
    // }

    // sudo eBFP/blazesym/target/debug/blazecli symbolize process --pid 259062 0x005642ad65d095
    // 0x005642ad65d095: _start @ 0x1070+0x25

    // for(std::size_t i = 0; i < std::size(addrs); i++)
    // {
    //     std::print("    #{:<2} {:#018x} in {:<20}",
    //         i, addrs[i],
    //         syms->syms[i].name ? syms->syms[i].name : "null");

    //     if (syms->syms[i].reason)
    //         std::println(" {}", blaze_symbolize_reason_str(syms->syms[i].reason));
    //     else
    //         std::println(" sym_addr: {:#018x}, sym_off: {:#010x}, name: {}:{}:{}",
    //             syms->syms[i].addr,
    //             syms->syms[i].offset,
    //             syms->syms[i].code_info.file ? syms->syms[i].code_info.file : "null",
    //             syms->syms[i].code_info.line,
    //             syms->syms[i].code_info.column);
    // }
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

        std::print("pid: {:>6}, tid: {:>6}, execve,  ret: {:>5}, command: ", 
            event->tgid, // pid
            event->pid,  // tid
            event->ret);
 
        auto& arg = map_[event->pid_tgid];
        arg.ret = event->ret;

        std::ranges::copy(arg.argv, std::ostream_iterator<decltype(arg.argv)::value_type>{std::cout, " "});
        std::println();
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

        std::println("pid: {:>6}, tid: {:>6}, kill,    ret: {:>5}, target pid: {}, signal: {}",
            event->tgid, // pid
            event->pid,  // tid
            event->ret,
            arg.target_pid,
            arg.signal);

        arg.ret = event->ret;
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

        auto result  = std::copy_n(event->buf, event->size, std::begin(content) + event->index);
        if  (result != std::end(content))
            return;

        constexpr std::array<char, 4> elf_magic{ 0x7F, 'E', 'L', 'F' };

        auto pair = std::ranges::mismatch(content, elf_magic);
        if  (pair.in2 == std::end(elf_magic))
        {
            std::println("elf file");
        }
        else
        {
            std::ranges::copy(content, std::ostreambuf_iterator<char>(std::cout));
            std::println();
        }
    }
};

class sys_exit_read_handler
{
    std::unordered_map<__u64, read_argument>& map_;
    std::unordered_map<path, std::string, path_hash, path_equal>& path_map_;

public:
    sys_exit_read_handler(decltype(map_) map, decltype(path_map_) path_map) :
        map_{map},
        path_map_{path_map}
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

        std::println("pid: {:>6}, tid: {:>6}, read,    ret: {:>5}, fd: {:>3}, {} ({}), name: \"{}\"", 
            event->tgid, // pid
            event->pid,  // tid
            event->ret,
            event->fd,
            permission,
            mode,
            path_map_[event->path]);

        if (event->ret >= 0)
        {
            map_[event->pid_tgid].resize(event->ret);
        }
    }
};

class path_handler
{
    std::unordered_map<path, std::string, path_hash, path_equal>& map_;
    bpf_map *path_map_;

public:
    path_handler(decltype(map_) map, decltype(path_map_) path_map) :
        map_{map},
        path_map_{path_map}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<path_event*>(data);

        std::array<char, MAX_ARG_LEN> buffer;
        auto error = bpf_map__lookup_elem(path_map_,
                                          &event->path, sizeof(event->path),
                                          std::data(buffer), sizeof(buffer), 0);
        if  (error < 0)
        {
            std::println("error: bpf_map__lookup_elem < 0");
            return;
        }

        auto [_, inserted] = map_.insert_or_assign(
            event->path,
            std::string{std::begin(buffer) + event->index,
                        std::begin(buffer) + MAX_ARG_LEN - MAX_NAME_LEN});

        if (inserted == false)
        {
            std::println("error: insert_or_assign.inserted == false");
        }
    }
};

class vm_area_handler
{
    std::unordered_map<__u64, std::vector<vm_area_event::vm_area>>& map_;
    std::unordered_map<path,  std::string, path_hash, path_equal>& path_map_;
    std::unordered_map<int, __u64> ktime_map_;

public:
    vm_area_handler(decltype(map_) map, decltype(path_map_) path_map) :
        map_{map},
        path_map_{path_map}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<vm_area_event*>(data);

        auto& areas = map_[event->pid_tgid];

        if (auto& ktime = ktime_map_[cpu];
            ktime != event->ktime)
        {
            ktime  = event->ktime;
            areas.clear();
        }

        for (auto& area : event->area)
        {
            if (area.vm_start == 0)
            {
                std::println("pid: {:>6}, tid: {:>6}, vm_area, size: {}",
                    event->tgid,
                    event->pid,
                    areas.size());

                for (const auto& entry : areas)
                {
                    std::println("    {:#018x} {:#018x} {:#010x} {:p} {:p} name: {}",
                    entry.vm_start,
                    entry.vm_end,
                    entry.vm_pgoff * 4096,
                    entry.path.dentry,
                    entry.path.mnt,
                    path_map_[entry.path]);
                }
                break;
            }
            
            areas.emplace_back(area);
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

class sys_exit_handler
{
    blaze_normalizer* normalizer_;
    blaze_symbolizer* symbolizer_;
    bpf_map* stack_trace_;

public:
    sys_exit_handler(blaze_normalizer* normalizer, blaze_symbolizer* symbolizer, bpf_map* stack_trace) :
        normalizer_{normalizer},
        symbolizer_{symbolizer},
        stack_trace_{stack_trace}
    {}

    void operator()(int cpu, void *data, __u32 size)
    {
        auto event = static_cast<sys_exit_event*>(data);

        std::println("pid: {:>6}, tid: {:>6}, syscall, ret: {:>5}, number: {}", 
            event->tgid,
            event->pid,
            event->ret,
            event->syscall_nr
        );

        std::array<__u64, PERF_MAX_STACK_DEPTH> stack;
        int error = bpf_map__lookup_elem(stack_trace_,
                                         &event->stack_id, sizeof(event->stack_id),
                                         std::data(stack), sizeof(stack), 0);
        if (error < 0)
            return;
        
        std::span<decltype(stack)::value_type> addrs{
            std::begin(stack),
            std::ranges::find(stack, 0)};

        print_stack_trace(normalizer_, symbolizer_, event->tgid, addrs);
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

template<typename Container, typename size_type = Container::size_type>
auto set_ret(Container& container, size_type bit)
{
    using value_type = typename Container::value_type;

    return container[bit / (sizeof(value_type) * 8)] |= 1 << bit % (sizeof(value_type) * 8);
}

int main(int argc, char *argv[])
{
    if (SIG_ERR == std::signal(SIGINT,  signal_handler)) return EXIT_FAILURE;
    if (SIG_ERR == std::signal(SIGTERM, signal_handler)) return EXIT_FAILURE;

    // open eBPF skeleton
    auto skeleton = std::unique_ptr<signal_bpf, decltype(&signal_bpf::destroy)>{
                                    signal_bpf::open(),   signal_bpf::destroy};
    if (!skeleton)
        return EXIT_FAILURE;

    int  error = 0;
    bool disable_read = true;
    if  (disable_read)
    {
        if ((error = bpf_program__set_autoload(skeleton->progs.tracepoint__syscalls__sys_enter_read, false)) < 0)
            return EXIT_FAILURE;
        if ((error = bpf_program__set_autoload(skeleton->progs.tracepoint__syscalls__sys_exit_read, false)) < 0)
            return EXIT_FAILURE;
    }

    // load eBPF skeleton
    if ((error = signal_bpf::load(skeleton.get())) < 0)
        return EXIT_FAILURE;

    __u32 zero = 0;
    char pattern[MAX_ARG_LEN] = "";

    // update pattern to bpf map
    if ((error = bpf_map__update_elem(skeleton->maps.command_pattern,
                                      &zero, sizeof(zero),
                                      pattern, sizeof(pattern), BPF_ANY)) < 0)
        return EXIT_FAILURE;

    // update read_content flag to bpf map
    if ((error = bpf_map__update_elem(skeleton->maps.read_content,
                                      &zero, sizeof(zero),
                                      &zero, sizeof(zero), BPF_ANY)) < 0)
        return EXIT_FAILURE;

    struct stat st{};
    if ((error = stat("/proc/self/ns/pid", &st)) < 0)
        return EXIT_FAILURE;

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
        return EXIT_FAILURE;

    std::array<__u64, MAX_SYSCALL> negative_ret{};
    set_ret(negative_ret, __NR_open);
    set_ret(negative_ret, __NR_openat);
    set_ret(negative_ret, __NR_openat2);

    // update negative_ret to bpf map
    if ((error = bpf_map__update_elem(skeleton->maps.negative_ret_map,
                                      &zero, sizeof(zero),
                                      std::data(negative_ret), sizeof(negative_ret), BPF_ANY)) < 0)
        return EXIT_FAILURE;

    // attach eBPF 程式到對應的 tracepoint
    if ((error = signal_bpf::attach(skeleton.get())) < 0)
        return EXIT_FAILURE;

    // const char *debug_dirs[] = { "/usr/lib/debug",
    //                              "/usr/lib/debug/.build-id" };

    blaze_symbolizer_opts symbolizer_opts =
    {
        .type_size = sizeof(symbolizer_opts),
        // .debug_dirs = std::data(debug_dirs),
        // .debug_dirs_len = std::size(debug_dirs),
        // .auto_reload = true, // 可選：若 ELF 檔有變更，自動 reload
        .code_info = true,   // 啟用 DWARF 行號資訊解析
        // .inlined_fns = true, // 可選：還原 inline 函數
        // .demangle = true     // 可選：還原 C++ / Rust 函數名稱
    };

    auto symbolizer = std::unique_ptr<blaze_symbolizer, decltype(&blaze_symbolizer_free)>{
        blaze_symbolizer_new_opts(&symbolizer_opts),
        blaze_symbolizer_free};
    if (!symbolizer)
    {
        std::println("blaze_symbolizer_new_opts: {}", blaze_err_str(blaze_err_last()));
        return EXIT_FAILURE;
    }

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
    {
        std::println("blaze_normalizer_new_opts: {}", blaze_err_str(blaze_err_last()));
        return EXIT_FAILURE;
    }

    std::unordered_map<__u64, execve_argument> execve_map;
    std::unordered_map<__u64, kill_argument> kill_map;
    std::unordered_map<__u64, read_argument> read_map;
    std::unordered_map<__u64, std::vector<vm_area_event::vm_area>> vm_area_map;
    std::unordered_map<path,  std::string, path_hash, path_equal> path_map;
    
    event_handler<EVENT_MAX> handler;
    handler[EVENT_ID(sys_enter_execve_event)]   = sys_enter_execve_handler{execve_map};
    handler[EVENT_ID(sys_exit_execve_event)]    = sys_exit_execve_handler{execve_map};
    handler[EVENT_ID(sys_enter_kill_event)]     = sys_enter_kill_handler{kill_map};
    handler[EVENT_ID(sys_exit_kill_event)]      = sys_exit_kill_handler{kill_map};
    handler[EVENT_ID(sys_enter_read_event)]     = sys_enter_read_handler{read_map};
    handler[EVENT_ID(sys_exit_read_event)]      = sys_exit_read_handler{read_map, path_map};
    handler[EVENT_ID(path_event)]               = path_handler{path_map, skeleton->maps.path_map};
    handler[EVENT_ID(vm_area_event)]            = vm_area_handler{vm_area_map, path_map};
    handler[EVENT_ID(sched_process_exit_event)] = handle_sched_process_exit;
    handler[EVENT_ID(do_coredump_event)]        = do_coredump_handler{symbolizer.get(), skeleton->maps.stack_trace};
    handler[EVENT_ID(sys_exit_event)]           = sys_exit_handler{normalizer.get(), symbolizer.get(), skeleton->maps.stack_trace};
    
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