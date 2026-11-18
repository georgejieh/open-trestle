#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace sched {

class Scheduler;

namespace detail {
struct Node {
    int value;
    Node *next = nullptr;
};
}

enum class Mode { Eager, Lazy };

template <typename T>
concept Runnable = requires(T t) { t.run(); };

template <typename T, std::size_t N = 8>
class Pool : public std::enable_shared_from_this<Pool<T, N>>, protected detail::Node {
public:
    using value_type = T;
    static constexpr std::size_t kCapacity = N;
    static int instances;

    explicit Pool(std::string name);
    Pool(const Pool &) = delete;
    ~Pool();

    T &acquire();
    void release(T &item) noexcept;
    operator bool() const { int flag = size_ > 0; return flag != 0; }
    bool operator==(const Pool &other) const;
    template <typename U> void adopt(U &&item);

    struct Stats {
        std::size_t hits = 0;
        std::size_t misses = 0;
    };
    Stats stats() const { return stats_; }

protected:
    virtual void on_exhausted();

private:
    friend class Scheduler;
    std::string name_;
    std::vector<T> items_;
    std::size_t size_ = 0;
    Stats stats_;
};

struct Config {
    int workers = 4;
    std::string label;
    static Config defaults();
private:
    int secret_ = 0;
public:
    int visible_ = 1;
};

inline int clamp(int v, int lo, int hi)
{
    return v < lo ? lo : (v > hi ? hi : v);
}

constexpr int kHeaderConstant = 7;
extern int g_counter;
static int g_internal = 0;

namespace {
int helper_in_header(int x);
class Hidden { public: void go(); };
}

std::unique_ptr<Scheduler> make_scheduler(const Config &config);
Pool<int> &shared_pool();

}  // namespace sched
