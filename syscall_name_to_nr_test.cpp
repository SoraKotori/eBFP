#include <string_view>
#include <vector>
#include <optional>
#include <print>

#include "syscall_name_to_nr.h"  // 提供 struct syscall_entry 與 C 版 API

// 便利包裝：用 string_view 呼叫 C 版 API
static inline const syscall_entry* lookup(std::string_view s) {
    return syscall_name_to_nr(s.data(), s.size());
}

int main(int argc, char** argv) {
    int failed = 0;

    // 若帶參數：逐一查詢並列印
    if (argc > 1) {
        for (int i = 1; i < argc; ++i) {
            std::string_view key{argv[i]};
            if (const auto* e = lookup(key)) {
                std::println("{} -> {}", key, e->nr);
            } else {
                std::println("{} -> (not found)", key);
            }
        }
        return 0;
    }

    // 內建測試案例（來自你的 .gperf 表）
    struct Case { std::string_view key; std::optional<int> expect; };
    const std::vector<Case> cases = {
        {"read", 0},
        {"write", 1},
        {"open", 2},
        {"io_uring_setup", 425},
        {"nosuch_syscall", std::nullopt}, // 不存在
        {"Read", std::nullopt},           // gperf 預設區分大小寫
    };

    for (const auto& c : cases) {
        const auto* e = lookup(c.key);
        if (c.expect.has_value()) {
            if (!e) {
                std::println("[FAIL] {} expected nr={}, but not found", c.key, *c.expect);
                ++failed;
            } else if (e->nr != *c.expect) {
                std::println("[FAIL] {} expected nr={}, got {}", c.key, *c.expect, e->nr);
                ++failed;
            } else {
                std::println("[ OK ] {} -> {}", c.key, e->nr);
            }
        } else {
            if (e) {
                std::println("[FAIL] {} expected not found, but got nr={}", c.key, e->nr);
                ++failed;
            } else {
                std::println("[ OK ] {} -> not found (as expected)", c.key);
            }
        }
    }

    if (failed == 0) {
        std::println("All tests passed.");
        return 0;
    } else {
        std::println("{} test(s) failed.", failed);
        return 1;
    }
}
