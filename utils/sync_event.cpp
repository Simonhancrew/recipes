#include "sync_event.h"

namespace base {
namespace utils {

void SyncEvent::Set() {
  std::lock_guard<std::mutex> _(lock_);
  status_ = true;
  cv_.notify_one();
}

WaitRes SyncEvent::Wait(int wait_for_ms) {
  auto ret = WaitRes::kInvalid;

  std::unique_lock<std::mutex> l(lock_);

  if (status_) {
    status_ = false;
    return WaitRes::kValid;
  }

  if (wait_for_ms == 0) {
    return WaitRes::kInvalid;
    ;
  }

  if (wait_for_ms < 0) {
    cv_.wait(l, [this] { return status_; });
    ret = WaitRes::kValid;
  } else {
    auto final_res = cv_.wait_for(l, std::chrono::milliseconds(wait_for_ms),
                                  [this] { return status_; });
    ret = (final_res ? WaitRes::kValid : WaitRes::kInvalid);
  }
  // here just reset it by default
  // if want manual reset, impl a Reset()
  status_ = false;
  return ret;
}

}  // namespace utils
}  // namespace base
