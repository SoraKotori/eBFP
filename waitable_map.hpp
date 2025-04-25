#include <flat_map>

template<typename Key,
         typename T,
         typename MappedContainer = std::unordered_map<Key, T>>
class waitable_map
{
public:
    struct wait_handle
    {
        MappedContainer::iterator wait_iterator;
        std::coroutine_handle<> head_handle = std::noop_coroutine();
    };

    struct map_awaiter
    {
        const MappedContainer& map;

        MappedContainer::iterator& wait_iterator;
        std::coroutine_handle<>& head_handle;

        bool await_ready() const
        {
            return std::end(map) != wait_iterator;
        }

        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> handle)
        {
            auto origin_resume = handle.promise().resume_handle();

            // head = coroutine3 -> coroutine2 -> coroutine1 -> noop
            handle.promise().resume_handle() = head_handle;
            head_handle = handle;

            return origin_resume;
        }

        auto await_resume()
        {
            return wait_iterator;
        }
    };

    template<typename... Args>
    auto emplace(Args&&... args)
    {
        auto pair = map_.emplace(std::forward<Args>(args)...);

        auto handle_iterator = wait_handles_.find(pair.first->first);
        if  (handle_iterator != std::end(wait_handles_))
        {
            handle_iterator->second.wait_iterator = pair.first->second.wait_iterator;
            handle_iterator->second.head_handle.resume();

            wait_handles_.erase(handle_iterator);
        }

        return pair;
    }

    template<typename K>
    auto find(K&& key)
    {
        auto map_it = map_.find(std::forward<K>(key));
        if  (map_it == std::end(map_))
        {
            auto [wait_iterator, head_handle] = wait_handles_[std::forward<K>(key)];
            return map_awaiter{map_, std::move(wait_iterator), std::move(head_handle)};
        }
        return map_awaiter{map_, map_it, std::noop_coroutine()};
    }

private:
    MappedContainer map_;
    std::flat_map<Key, wait_handle> wait_handles_;
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

Task coroutine(waitable_map<__u64, path>& map)
{
    return {};
}
