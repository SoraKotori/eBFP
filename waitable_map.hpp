#include <flat_map>

template<typename Key,
         typename T,
         typename MapContainer = std::unordered_map<Key, T>>
class waitable_map
{
public:
    struct suspended_coroutine;

    using map_container_type = MapContainer;
    using coroutine_container_type = std::flat_map<Key, suspended_coroutine>;

    using map_iterator = typename map_container_type::iterator;
    using coroutine_reference = typename coroutine_container_type::mapped_type&;

    struct suspended_coroutine
    {
        // head handle: coroutine3 -> coroutine2 -> coroutine1 -> noop
        std::coroutine_handle<> waiting_handles = std::noop_coroutine();
        map_iterator            waiting_iterator;
    };

    struct map_awaiter
    {
        std::variant<map_iterator, coroutine_reference> variant;

        auto await_ready() const
        {
            return std::holds_alternative<map_iterator>(variant);
        }

        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> current_handle)
        {
            auto&  resume_handle = current_handle.promise().resume_handle();
            auto& waiting_handle = std::get<coroutine_reference>(variant).waiting_handles;

            // resume_handle <- waiting_handle <- current_handle
            return std::exchange(resume_handle, std::exchange(waiting_handle, current_handle));
        }

        auto await_resume() const
        {
            return std::holds_alternative<map_iterator>(variant) ?
                std::get<map_iterator>(variant) :
                std::get<coroutine_reference>(variant).waiting_iterator;
        }
    };

    template<typename... Args>
    auto emplace(Args&&... args)
    {
        auto pair = map_.emplace(std::forward<Args>(args)...);

                                             // pair.iterator->key
        auto handle_iterator = coroutines_.find(pair.first->first);
        if  (handle_iterator != std::end(coroutines_))
        {
                                                 // pair.iterator->value.wait_iterator
            handle_iterator->second.wait_iterator = pair.first->second.wait_iterator;
            handle_iterator->second.waiting_handles.resume();

            coroutines_.erase(handle_iterator);
        }

        return pair;
    }

    template<typename K>
    map_awaiter find(K&& key)
    {
        auto map_it = map_.find(std::forward<K>(key));
        if  (map_it == std::end(map_))
            return {coroutines_[std::forward<K>(key)].second}; // 插入後，在插入元素之後的 reference 會失效
        else
            return {map_it};
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

Task coroutine(waitable_map<__u64, path>& map)
{
    return {};
}
