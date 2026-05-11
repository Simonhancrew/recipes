//
// Timer Wheel
//
// Core idea: divide the timeline into N slots at a fixed granularity (tick).
// Each slot holds a linked list of timers that fire at that tick.
// Advancing time only requires iterating the current slot's list, O(1) per fire.
//
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <list>
#include <unordered_map>

namespace example {

class TimerWheel {
 public:
  static constexpr uint32_t kWheelSize = 256;  // number of slots
  static constexpr uint32_t kTickMs = 1;       // tick precision (ms)

  struct TimerEntry {
    uint64_t id;
    uint64_t expire_tick;       // tick at which this timer expires
    uint64_t interval_ticks;    // interval for persist timer (0 = one-shot)
    std::function<void()> cb;
  };

  using Slot = std::list<TimerEntry>;
  using Iterator = Slot::iterator;

  TimerWheel();

  // Create a timer, returns its id
  uint64_t CreateTimer(std::function<void()> cb, uint64_t ms, bool one_shot);

  // Cancel a timer, O(1)
  void Cancel(uint64_t id);

  // Advance one tick
  void Tick();

  // Advance by ms milliseconds
  void ForwardMs(uint64_t ms);

  uint64_t NowMs() const;

 private:
  struct Location {
    uint32_t slot_idx;
    Iterator iter;
  };

  std::array<Slot, kWheelSize> wheel_;
  std::unordered_map<uint64_t, Location> id_map_;  // id -> slot location
  uint64_t current_tick_;
  uint64_t next_id_;
};

}  // namespace example
