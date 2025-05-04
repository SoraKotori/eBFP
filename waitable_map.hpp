#include <coroutine>
#include <utility>
#include <exception>
#include <print>
#include <variant>

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
        // awaiter instance 本身會被存放在 coroutine frame 中
        coroutine_handle_type resume_handle;

        auto await_ready() noexcept
        {
            // 如果沒有指定 resume_handle，則可以直接結束，不 suspend
            return !resume_handle;
        }

        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> handle) noexcept
        {
            // 在呼叫 destroy() 之前，先將要回傳的 handle 複製到 stack 上的 local 變數
            // 避免下面 destroy() 釋放 coroutine frame 後，再去讀取已被釋放的記憶體，引發 UAF
            auto local_handle = resume_handle;

            // destroy() 可能會因為 promise_type 的 destructor 拋出 exception，
            // 並且因為 final_suspend 要求 noexcept，所以需要 try-catch 以避免直接觸發 std::terminate()
            // 或考慮將 destroy() 移動到外部處理
            try
            {
                // 釋放整個 coroutine frame（包含 promise, local coroutine 變數，還有 final_awaiter 本身)
                handle.destroy();
            }
            catch(const std::exception& exception)
            {
                std::println("final destroy exception: {}", exception.what());
            }

            return local_handle;
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
        // 若需要 suspend，則需要手動呼叫 destroy()
        return final_awaiter{resume_handle};
    }

    auto return_void() {}
    auto unhandled_exception() {}
};

template<template<typename...> typename MapContainer,
         typename ContainerKey,
         typename T,
         typename... ContainerArgs>
class waitable_map
{
public:
    using map_container_type = MapContainer<ContainerKey, T, ContainerArgs...>;
    using map_key_type = typename map_container_type::key_type;
    using map_iterator = typename map_container_type::iterator;

    // coroutine chain: coroutine3 -> coroutine2 -> coroutine1 -> nullptr
    using coroutine_container_type = MapContainer<ContainerKey, std::coroutine_handle<promise>, ContainerArgs...>;
    using coroutine_key_type = typename coroutine_container_type::key_type;

    // coroutine container 插入元素後，原本的 iterators 和 references 可能會失效，
    // 因此無法保存在 map_awaiter 中，作為 await_resume 時所使用，解決方法:
    // 1. 保存 container 和 key，每次重新查詢
    // 2. 改用 std::map 基於 node-based 的方法，確保 iterators 和 references 不會失效
    // 3. 改用 std::unordered_map，確保 references 不會失效 (https://eel.is/c++draft/unord.req#general-9)
    // 4. 使用 boost::stable_vector 或 std::unique_ptr，確保 iterators 和 references 不會失效
    template<typename Key>
    struct await_key
    {
        const map_container_type& map;
        coroutine_container_type& coroutines;
        const Key& key;
    };

    template<typename Key>
    struct map_awaiter : std::variant<map_iterator, await_key<Key>>
    {
        // 使用 base::constructor 來初始化 map_awaiter
        using std::variant<map_iterator, await_key<Key>>::variant;

        auto await_ready() const
        {
            return std::holds_alternative<map_iterator>(*this);
        }

        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> current_handle) -> std::coroutine_handle<>
        {
            auto [_, coroutines, key] = std::get<await_key<Key>>(*this);

            auto&  resume_handle = current_handle.promise().resume_handle;
            auto& waiting_handle = coroutines[key];

            // resume_handle <- waiting_handle <- current_handle
            if (auto handle = std::exchange(resume_handle, std::exchange(waiting_handle, current_handle)))
                return handle;
            else
                return std::noop_coroutine();
        }

        auto await_resume() const
        {
            return std::holds_alternative<map_iterator>(*this) ?
                std::get<map_iterator>(*this) :
                std::get<await_key<Key>>(*this).map.find(std::get<await_key<Key>>(*this).key);
        }
    };

    template<typename Key, typename Mapped>
    auto insert_or_assign(Key&& key, Mapped&& obj)
    {
        auto pair = map_.insert_or_assign(std::forward<Key>(key), std::forward<Mapped>(obj));
        if (!pair.second) // pair.bool
            return pair;

        auto iteraotr  = coroutines_.find(std::forward<Key>(key));
        if  (iteraotr != coroutines_.end())
        {
            // 先 move 出來再 erase，避免 resume() 插入新元素時 invalid iterator
            auto handle = std::move(iteraotr->second);

            coroutines_.erase(iteraotr);
            handle.resume();
        }

        return pair;
    }

    template<typename Key, typename... Args>
    auto try_emplace(Key&& key, Args&&... args)
    {
        auto pair = map_.try_emplace(std::forward<Key>(key), std::forward<Args>(args)...);
        if (!pair.second) // pair.bool
            return pair;

        auto iteraotr  = coroutines_.find(std::forward<Key>(key));
        if  (iteraotr != coroutines_.end())
        {
            // 先 move 出來再 erase，避免 resume() 插入新元素時 invalid iterator
            auto handle = std::move(iteraotr->second);

            coroutines_.erase(iteraotr);
            handle.resume();
        }

        return pair;
    }

    template<typename Key>
    auto find(const Key& key)
    {
        return map_.find(key);
    }

    template<typename Key>
    auto async_find(const Key& key)
    {
        auto map_it =  map_.find(key);
        if  (map_it == map_.end())
            return map_awaiter<Key>{std::in_place_type<await_key<Key>>, map_, coroutines_, key};
        else
            return map_awaiter<Key>{map_it};
    }

    auto end() noexcept
    {
        return map_.end();
    }

private:
    map_container_type map_;
    coroutine_container_type coroutines_;
};
