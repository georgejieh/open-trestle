#include <iostream>
#include "scheduler.hpp"

namespace fs = std::filesystem;
namespace outer::inner {
int deep_value = 3;
}

using namespace outer::inner;
using outer::inner::deep_value;

namespace {
int hidden_counter = 0;
void hidden_helper() { ++hidden_counter; }
}

namespace sched {

template <typename T, std::size_t N>
int Pool<T, N>::instances = 0;

template <typename T, std::size_t N>
Pool<T, N>::Pool(std::string name) : name_(std::move(name)) {}

template <typename T, std::size_t N>
Pool<T, N>::~Pool() = default;

template <typename T, std::size_t N>
T &Pool<T, N>::acquire()
{
    if (size_ == items_.size()) {
        on_exhausted();
    }
    return items_[size_++];
}

template <typename T, std::size_t N>
bool Pool<T, N>::operator==(const Pool &other) const
{
    return name_ == other.name_;
}

Config Config::defaults()
{
    Config c;
    std::vector<int> numbers(10);
    std::string text("hello");
    Config copy(c);
    std::unique_ptr<Pool<int>> pool(new Pool<int>("p"));
    auto fn = [&](int x) { int doubled = x * 2; return doubled; };
    int local_array[3] = {1, 2, 3};
    static_cast<void>(fn);
    return c;
}

void *operator new(std::size_t n)
{
    return ::operator new(n);
}

}  // namespace sched

namespace detail_ns {
int alpha = 1, beta = 2;
extern "C" int c_linkage(int x);
extern "C" {
void block_one(void);
int block_two(int);
}
}

[[nodiscard]] static int attributed(int x);
struct [[deprecated("old")]] Old {};
class Derived final : public sched::Config, public virtual std::exception {
public:
    Derived() : sched::Config() {}
    int run() const override;
};

int main()
{
    sched::Pool<int> p("main");
    int &ref = p.acquire();
    std::cout << ref << std::endl;
    return outer::inner::deep_value;
}
