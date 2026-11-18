// scheduler.cpp: a task scheduler with priorities, worker threads and
// a small metrics registry, written with templates and RAII helpers.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#include "scheduler/clock.hpp"

using namespace std::chrono_literals;
using std::string;
using Millis = std::chrono::milliseconds;

#define SCHED_ASSERT(cond) do { if (!(cond)) std::abort(); } while (0)

namespace sched {

constexpr int kDefaultWorkers = 4;
constexpr std::size_t kMaxQueue = 1 << 16;
static const char *const kVersion = "2.1.0";

enum class Priority { Low, Normal, High };

enum Flags : unsigned { None = 0, Detached = 1, Retry = 2 };

using TaskFn = std::function<void()>;
typedef std::size_t TaskId;

template <typename T>
using Ref = std::shared_ptr<T>;

class Error : public std::runtime_error {
public:
    explicit Error(const std::string &what) : std::runtime_error(what) {}
};

struct Task {
    TaskId id;
    Priority priority;
    TaskFn fn;
    std::string label;

    bool operator<(const Task &other) const {
        return priority < other.priority;
    }
};

class Clock {
public:
    virtual ~Clock() = default;
    virtual std::chrono::steady_clock::time_point now() const = 0;
};

class SystemClock final : public Clock {
public:
    std::chrono::steady_clock::time_point now() const override {
        return std::chrono::steady_clock::now();
    }
};

template <typename T, typename Compare = std::less<T>>
class BoundedQueue {
public:
    explicit BoundedQueue(std::size_t limit) : limit_(limit) {}

    bool push(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (items_.size() >= limit_) {
            return false;
        }
        items_.push(std::move(item));
        ready_.notify_one();
        return true;
    }

    std::optional<T> pop(Millis timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!ready_.wait_for(lock, timeout, [this] { return !items_.empty(); })) {
            return std::nullopt;
        }
        T item = items_.top();
        items_.pop();
        return item;
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return items_.size();
    }

private:
    std::size_t limit_;
    mutable std::mutex mutex_;
    std::condition_variable ready_;
    std::priority_queue<T, std::vector<T>, Compare> items_;
};

class Counter {
public:
    Counter() = default;
    Counter(const Counter &) = delete;
    Counter &operator=(const Counter &) = delete;

    void add(long n = 1) { value_.fetch_add(n, std::memory_order_relaxed); }
    long value() const { return value_.load(); }

private:
    std::atomic<long> value_{0};
};

class Registry {
public:
    static Registry &instance();

    Counter &counter(const std::string &name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = counters_.find(name);
        if (it == counters_.end()) {
            it = counters_.emplace(name, std::make_unique<Counter>()).first;
        }
        return *it->second;
    }

    std::map<std::string, long> snapshot() const;

private:
    mutable std::mutex mutex_;
    std::map<std::string, std::unique_ptr<Counter>> counters_;
};

Registry &Registry::instance()
{
    static Registry registry;
    return registry;
}

std::map<std::string, long> Registry::snapshot() const
{
    std::map<std::string, long> out;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &entry : counters_) {
        out[entry.first] = entry.second->value();
    }
    return out;
}

class ScopedTimer {
public:
    ScopedTimer(Counter &total, const Clock &clock)
        : total_(total), clock_(clock), start_(clock.now()) {}
    ~ScopedTimer() {
        auto elapsed = clock_.now() - start_;
        total_.add(std::chrono::duration_cast<Millis>(elapsed).count());
    }

private:
    Counter &total_;
    const Clock &clock_;
    std::chrono::steady_clock::time_point start_;
};

class Scheduler {
public:
    Scheduler(int workers, Ref<Clock> clock);
    Scheduler(const Scheduler &) = delete;
    ~Scheduler();

    TaskId submit(Priority priority, std::string label, TaskFn fn);
    template <typename F, typename... Args>
    TaskId submit_bound(Priority priority, F &&f, Args &&...args);
    void shutdown();
    std::size_t pending() const { return queue_.size(); }

    static constexpr int kMaxRetries = 3;

protected:
    virtual void on_error(const Task &task, const std::exception &e);

private:
    void run_worker(int index);

    BoundedQueue<Task> queue_;
    std::vector<std::thread> threads_;
    std::atomic<bool> stopping_{false};
    std::atomic<TaskId> next_id_{1};
    Ref<Clock> clock_;
};

Scheduler::Scheduler(int workers, Ref<Clock> clock)
    : queue_(kMaxQueue), clock_(std::move(clock))
{
    SCHED_ASSERT(workers > 0);
    for (int i = 0; i < workers; ++i) {
        threads_.emplace_back(&Scheduler::run_worker, this, i);
    }
}

Scheduler::~Scheduler()
{
    shutdown();
}

TaskId Scheduler::submit(Priority priority, std::string label, TaskFn fn)
{
    Task task{next_id_++, priority, std::move(fn), std::move(label)};
    TaskId id = task.id;
    if (!queue_.push(std::move(task))) {
        throw Error("queue full");
    }
    Registry::instance().counter("submitted").add();
    return id;
}

template <typename F, typename... Args>
TaskId Scheduler::submit_bound(Priority priority, F &&f, Args &&...args)
{
    auto bound = std::bind(std::forward<F>(f), std::forward<Args>(args)...);
    return submit(priority, "bound", [bound]() mutable { bound(); });
}

void Scheduler::shutdown()
{
    if (stopping_.exchange(true)) {
        return;
    }
    for (auto &t : threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
}

void Scheduler::on_error(const Task &task, const std::exception &e)
{
    Registry::instance().counter("failed").add();
    (void)task;
    (void)e;
}

void Scheduler::run_worker(int index)
{
    auto &busy = Registry::instance().counter("busy_ms");
    while (!stopping_.load()) {
        auto next = queue_.pop(50ms);
        if (!next) {
            continue;
        }
        ScopedTimer timer(busy, *clock_);
        try {
            next->fn();
        } catch (const std::exception &e) {
            on_error(*next, e);
        } catch (...) {
            Registry::instance().counter("unknown_errors").add();
        }
    }
    (void)index;
}

namespace detail {

template <typename It, typename Pred>
It find_last(It first, It last, Pred pred)
{
    It result = last;
    for (; first != last; ++first) {
        if (pred(*first)) {
            result = first;
        }
    }
    return result;
}

inline std::string describe(Priority p)
{
    switch (p) {
    case Priority::Low: return "low";
    case Priority::Normal: return "normal";
    case Priority::High: return "high";
    }
    return "?";
}

} // namespace detail

namespace tools {

class LoggingScheduler : public Scheduler, private Counter {
public:
    using Scheduler::Scheduler;

protected:
    void on_error(const Task &task, const std::exception &e) override
    {
        std::string_view what = e.what();
        Registry::instance().counter("logged").add(static_cast<long>(what.size()));
        Scheduler::on_error(task, e);
    }
};

std::string report(const Registry &registry)
{
    std::string out;
    for (auto &[name, value] : registry.snapshot()) {
        out += name + "=" + std::to_string(value) + "\n";
    }
    return out;
}

} // namespace tools

} // namespace sched

int main()
{
    auto clock = std::make_shared<sched::SystemClock>();
    sched::tools::LoggingScheduler scheduler(sched::kDefaultWorkers, clock);
    for (int i = 0; i < 10; ++i) {
        scheduler.submit(sched::Priority::Normal, "job", [i] { (void)i; });
    }
    scheduler.submit_bound(sched::Priority::High, [](int x) { return x * 2; }, 21);
    scheduler.shutdown();
    return sched::tools::report(sched::Registry::instance()).empty() ? 1 : 0;
}
