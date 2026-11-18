// A C++ header with the .h extension: analysed as C++, not as C.
#ifndef REGISTRY_H
#define REGISTRY_H

#include <map>
#include <string>
#include "handle.h"

namespace plugins {

enum class State { Loaded, Failed };

struct Descriptor {
    std::string name;
    int version = 0;
};

template <typename T>
class Registry {
public:
    explicit Registry(std::size_t capacity);
    ~Registry();

    bool add(const std::string &key, T value);
    const T *find(const std::string &key) const noexcept;
    std::size_t size() const { return entries_.size(); }

private:
    std::map<std::string, T> entries_;
    std::size_t capacity_;
};

class Loader : public Registry<Descriptor> {
public:
    using Registry::Registry;
    virtual State load(const std::string &path);
};

inline int registryVersion() { return 2; }

}  // namespace plugins

#endif
