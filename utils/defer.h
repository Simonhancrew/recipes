#pragma once

#include "macros.h"

namespace utils {

template <typename Fn>
class Defer {
 public:
  explicit Defer(const Fn& fn) : fn_(fn) {}
  ~Defer() { fn_(); }
  Defer(Defer&&) = delete;
  Defer() = delete;

 private:
  const Fn& fn_;
};

#define DEFER(...) Defer CAT2(defer, __LINE__)([&]() { __VA_ARGS__; })

}  // namespace utils
