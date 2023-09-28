#pragma once

#include <condition_variable>
#include <mutex>

namespace base {
namespace utils {

enum class WaitRes { kValid, kInvalid };

class SyncEvent {
 public:
  explicit SyncEvent(bool init = false) : status_(init) {}
  ~SyncEvent() = default;
  void Set();
  // default wait for -1, means forever wait
  WaitRes Wait(int wait_for_ms = -1);

  SyncEvent(const SyncEvent &) = delete;
  const SyncEvent &operator=(const SyncEvent &) = delete;

 private:
  std::condition_variable cv_;
  std::mutex lock_;
  bool status_{false};
};

}  // namespace utils
}  // namespace base
