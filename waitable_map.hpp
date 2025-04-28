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

    // coroutine chain: coroutine3 -> coroutine2 -> coroutine1 -> nullptr
    using coroutine_container_type = MapContainer<Key, std::coroutine_handle<>, ContainerArgs...>;
    using coroutine_key_type = typename coroutine_container_type::key_type;

    struct map_awaiter
    {
        // coroutine container 插入元素後，原本的 iterators 和 references 可能會失效，
        // 因此無法保存在 map_awaiter 中，作為 await_resume 時所使用，解決方法:
        // 1. 保存 container 和 key，每次重新查詢
        // 2. 改用 std::map 基於 node-based 的方法
        // 3. 使用 boost::stable_vector 或 std::unique_ptr，確保 iterators 和 references 不會失效
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
        auto await_suspend(std::coroutine_handle<Promise> current_handle) -> std::coroutine_handle<>
        {
            auto [_, coroutines, key] = std::get<await_key>(variant);

            auto&  resume_handle = current_handle.promise().resume_handle;
            auto& waiting_handle = coroutines.try_emplace(key, std::noop_coroutine()).first;

            // resume_handle <- waiting_handle <- current_handle
            if (auto handle = std::exchange(resume_handle, std::exchange(waiting_handle, current_handle)))
                return handle;
            else
                return std::noop_coroutine();
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

        if (auto node = coroutines_.extract(std::forward<K>(key)))
            node.mapped.resume(); // handle.resume()

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

template<typename Promise>
struct Task : std::coroutine_handle<>
{
    using promise_type = Promise;
};

struct promise
{
    using coroutine_handle_type = std::coroutine_handle<promise>;

    coroutine_handle_type resume_handle;

    struct final_awaiter
    {
        auto await_ready() noexcept { return false; }

        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> std::coroutine_handle<>
        {
            try
            {
                // .promise() 並未標記為 noexcept，可能因為無效的 handle 拋出 exception
                auto resume_handle = handle.promise().resume_handle;

                // 可能會因為 promise_type 的 destructor 拋出例外，
                // 並且因為 final_suspend 要求 noexcept，所以需要 try-catch 以避免直接觸發 std::terminate()
                // 或考慮將 .destroy() 移動到外部處理
                handle.destroy();

                if (resume_handle)
                    return resume_handle;
            }
            catch(const std::exception& exception)
            {
                std::println("{}", exception.what());
            }

            return std::noop_coroutine();
        }

        auto await_resume() noexcept {}
    };

    auto get_return_object()
    {
        return Task<promise>{coroutine_handle_type::from_promise(*this)};
    }

    auto initial_suspend()
    {
        return std::suspend_never{};
    }

    // coroutine 的要求中規範 final_suspend 需要 noexcept
    auto final_suspend() noexcept
    {
        // 若不回傳 std::suspend_never，則需要手動呼叫 .destroy()
        return final_awaiter{};
    }

    auto return_void() {}
    auto unhandled_exception() {}
};

Task<promise> coroutine()
{
    waitable_map<std::unordered_map, __u64, path> map;

    co_return;
}
