#include <iostream>
#include <memory>

#include "signal.h"
#include "signal.skel.h"

int main(int argc, char *argv[])
{
    using unique_signal_t = std::unique_ptr<signal_bpf, decltype(&signal_bpf::destroy)>;

    unique_signal_t skel{signal_bpf::open_and_load(), &signal_bpf::destroy};
    if (skel == nullptr)
        return EXIT_FAILURE;

    if (auto error = signal_bpf::attach(skel.get()); error)
        return EXIT_FAILURE;

    return 0;
}