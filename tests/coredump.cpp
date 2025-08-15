#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>

#include <system_error>
#include <print>
#include <vector>

auto do_coredump()
{
    auto name = "no_exits.txt";
    auto fd = open(name, 0);

    std::vector<char> buffer(256);
    auto error = read(fd, buffer.data(), buffer.size());

    auto c = buffer[102400];

    close(fd);
}

int main()
{
    struct rlimit rlimit;
    if (getrlimit(RLIMIT_CORE, &rlimit) < 0)
        throw std::system_error{errno, std::system_category()};

    std::println("RLIMIT_CORE: rlim_cur: {}, rlim_max:{}", rlimit.rlim_cur, rlimit.rlim_max);

    if (auto env_value = getenv("RLIMIT_CORE"))
        rlimit.rlim_cur = atoi(env_value);
    else
        rlimit.rlim_cur = 0;

    if (setrlimit(RLIMIT_CORE, &rlimit) < 0)
        throw std::system_error{errno, std::system_category()};

    std::println("RLIMIT_CORE: rlim_cur: {}, rlim_max:{}", rlimit.rlim_cur, rlimit.rlim_max);

    do_coredump();
    
    std::println("done");
    return 0;
}