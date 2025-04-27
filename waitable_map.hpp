#include <unordered_map>

template<template<typename...> typename MapContainer,
         typename Key,
         typename T,
         typename... ContainerArgs>
class waitable_map
{
public:
    using map_container_type = MapContainer<Key, T, ContainerArgs...>;
    using map_key_type = typename map_container_type::key_type;
    using map_iterator = typename map_container_type::iterator;

    // coroutine chain: coroutine3 -> coroutine2 -> coroutine1 -> noop
    using coroutine_container_type = MapContainer<Key, std::coroutine_handle<>, ContainerArgs...>;
    using coroutine_key_type = typename coroutine_container_type::key_type;

    struct map_awaiter
    {
        // coroutine container 插入元素後，原本的 iterators 和 references 可能會失效，
        // 因此無法保存在 map_awaiter 中，作為 await_resume 時所使用，解決方法:
        // 1. 保存 container 和 key，每次重新查詢
        // 2. 改用 std::map 基於 node-based 的方法
        // 3. 使用 stable_vector 或 heap，確保 iterators 和 references 不會失效
        struct await_key
        {
            const map_container_type& map;
            coroutine_container_type& coroutines;
            const coroutine_key_type& key;
        };

        std::variant<map_iterator, await_key> variant;

        auto await_ready() const
        {
            return std::holds_alternative<map_iterator>(variant);
        }

        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> current_handle)
        {
            auto [_, coroutines, key] = std::get<await_key>(variant);

            auto&  resume_handle = current_handle.promise().resume_handle();
            auto& waiting_handle = coroutines.try_emplace(key, std::noop_coroutine()).first;

            // resume_handle <- waiting_handle <- current_handle
            return std::exchange(resume_handle, std::exchange(waiting_handle, current_handle));
        }

        auto await_resume() const
        {
            return std::holds_alternative<map_iterator>(variant) ?
                std::get<map_iterator>(variant) :
                std::get<await_key>(variant).map.find(std::get<await_key>(variant).key);
        }
    };

    template<typename K, typename... Args>
    auto try_emplace(K&& key, Args&&... args)
    {
        auto pair = map_.try_emplace(std::forward<K>(key), std::forward<Args>(args)...);
        if (!pair.second) // pair.bool
            return pair;

        if (auto node = coroutines_.extract(pair.first->first)) // pair.iterator->key_type
            node.mapped.resume(); // handle.resume

        return pair;
    }

    template<typename K>
    auto async_find(const K& key)
    {
        auto   map_it = map_.find(key);
        return map_it == std::end(map_) ? map_awaiter{map_, coroutines_, key}
                                        : map_awaiter{map_it};
    }

private:
    map_container_type map_;
    coroutine_container_type coroutines_;
};

struct Task
{
    class promise_type
    {
        std::coroutine_handle<promise_type> resume_handle_;

    public:
        Task get_return_object() { return {}; };
        auto initial_suspend()   { return std::suspend_never{}; }
        auto final_suspend()     { return std::suspend_never{}; }

        auto& resume_handle()    { return resume_handle_; }
    };
};

Task coroutine(waitable_map<std::unordered_map, __u64, path>& map)
{
    return {};
}
