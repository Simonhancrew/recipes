#pragma once

#include <memory>

template <typename T>
struct Maybe {
  Maybe() = default;
  ~Maybe() { is_valid = false; }
  explicit Maybe(const T& rhs) : is_valid(true), value(rhs) {}
  explicit Maybe(T&& rhs) : is_valid(true), value(std::move(rhs)) {}

  Maybe(const Maybe<T>& rhs) : is_valid(rhs.is_valid), value(rhs.value) {}
  Maybe(Maybe<T>&& rhs) noexcept
      : is_valid(rhs.is_valid), value(std::move(rhs.value)) {
    rhs.is_valid = false;
    // pod
    rhs.value = {};
  }

  Maybe<T>& operator=(const Maybe<T>& rhs) {
    if (&rhs == this) {
      return *this;
    }
    is_valid = true;
    value = rhs.value;
  }

  Maybe<T>& operator=(Maybe<T>&& rhs) noexcept {
    if (&rhs == this) {
      return *this;
    }
    is_valid = true;
    value = std::move(rhs.value);
    rhs.is_valid = false;
    // pod
    rhs.value = {};
    return *this;
  }

  bool is_valid{false};
  T value;
};
