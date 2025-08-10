#include "waitable_map.hpp"

#include <thread>
#include <map>
#include <unordered_map>
#include <flat_map>

Task<promise> coroutine(int i, waitable_map<std::flat_map, int, int>& map)
{
    auto iterator = co_await map.async_find(10);
    std::println("coroutine: {}, find string: {}", i, iterator->second);

    iterator = co_await map.async_find(20);
    std::println("coroutine: {}, find string: {}", i, iterator->second);

    co_return;
}

int main()
{
    waitable_map<std::flat_map, int, int> map;

    auto task1 = coroutine(1, map);
    auto task2 = coroutine(2, map);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    map.try_emplace(10, 100);
    map.insert_or_assign(20, 200);

    // 插入一個沒有任何 coroutine 在等待的 key 值，用來驗證 resume 的防護邏輯
    map.wait(30);                  // 為該 key 建立預設 null handle
    map.insert_or_assign(30, 300); // 不會觸發 resume 造成未定義的行為

    std::println("done");
    return 0;
}