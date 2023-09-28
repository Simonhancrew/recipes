#pragma once

#include <memory>

namespace base {
namespace utils {

template <typename T>
class Enum {
 public:
  explicit Enum() = default;
  ~Enum() { Reset(); }

  Enum(const Enum& ot) : valid_(ot.valid_), value_(ot.value_) {}
  Enum(Enum&& ot) noexcept : valid_(ot.valid_), value_(std::move(ot.value_)) {
    ot.Reset();
  }

  explicit Enum(const T& ot) : valid_(true), value_(ot) {}
  explicit Enum(T&& ot) : valid_(true), value_(std::move(ot)) {}

  Enum<T>& operator=(const Enum<T>& ot) {
    if (this == &ot) {
      return *this;
    }
    valid_ = ot.valid_;
    value_ = ot.value_;
    return *this;
  }

  Enum<T>& operator=(Enum<T>&& v) noexcept {
    if (this == &v) {
      return *this;
    }
    valid_ = v.valid_;
    value_ = std::move(v.value_);
    v.Reset();
    return *this;
  }

  void Reset() {
    valid_ = false;
    value_ = {};
  }

 private:
  bool valid_{false};
  T value_{};
};

}  // namespace utils
}  // namespace base
