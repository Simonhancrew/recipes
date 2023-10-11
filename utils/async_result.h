#pragma once

#include <mutex>
#include <queue>

#include "maybe.h"
#include "sync_event.h"

namespace base {
namespace utils {

template <typename T>
class AsyncRes {
 public:
  AsyncRes() = default;
  ~AsyncRes() {
    std::lock_guard<std::mutex> _(lock_);
    if (res_que_.empty()) {
      return;
    }
    std::queue<T> empty_que;
    std::swap(empty_que, res_que_);
  }

  Maybe<T> Wait(int wait_ms) {
    Maybe<T> res = WaitInternal(wait_ms);
    return res;
  }

  void Append(T&& value) {
    {
      std::lock_guard<std::mutex> _(lock_);
      res_que_.push(std::forward<T>(value));
    }
    // dont need lock here, lock inside
    event_.Set();
  }

 private:
  Maybe<T> WaitInternal(int ms) {
    bool need_wait = false;
    do {
      if (need_wait) {
        auto r = event_.Wait(ms);
        if (r != WaitRes::kValid) {
          return Maybe<T>::Invalid();
        }
      }

      std::lock_guard<std::mutex> _(lock_);
      if (res_que_.empty()) {
        need_wait = true;
        continue;
      }

      T res = res_que_.front();
      res_que_.pop();
      return Maybe<T>(res);
    } while (need_wait);
  }

  SyncEvent event_;
  // sync for the queue
  std::mutex lock_;
  std::queue<T> res_que_;
};

}  // namespace utils
}  // namespace base
