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

    // Insert a key without any awaiting coroutine to ensure resume guard works
    map.wait(30); // creates a default handle
    map.insert_or_assign(30, 300); // should not crash

    std::println("done");
    return 0;
}