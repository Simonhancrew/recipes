#include "utils/timer_wheel.h"

namespace example {

TimerWheel::TimerWheel() : current_tick_(0), next_id_(0) {}

uint64_t TimerWheel::CreateTimer(std::function<void()> cb, uint64_t ms, bool one_shot) {
  uint64_t interval_ticks = ms / kTickMs;
  uint64_t expire_tick = current_tick_ + interval_ticks;
  uint32_t slot_idx = expire_tick % kWheelSize;

  TimerEntry entry{next_id_, expire_tick, one_shot ? 0 : interval_ticks, std::move(cb)};
  auto it = wheel_[slot_idx].insert(wheel_[slot_idx].end(), entry);

  // Record location for O(1) cancel
  id_map_[next_id_] = {slot_idx, it};
  return next_id_++;
}

void TimerWheel::Cancel(uint64_t id) {
  auto map_it = id_map_.find(id);
  if (map_it == id_map_.end()) return;

  wheel_[map_it->second.slot_idx].erase(map_it->second.iter);
  id_map_.erase(map_it);
}

void TimerWheel::Tick() {
  current_tick_++;
  uint32_t slot_idx = current_tick_ % kWheelSize;

  // Iterate current slot, fire expired timers
  auto& slot = wheel_[slot_idx];
  auto it = slot.begin();
  while (it != slot.end()) {
    if (it->expire_tick > current_tick_) {
      // Not yet expired (wrapped around the wheel), skip
      ++it;
      continue;
    }

    // Fire
    auto cb = it->cb;  // copy to stack for safety
    uint64_t id = it->id;

    if (it->interval_ticks == 0) {
      // one-shot: remove and fire
      id_map_.erase(id);
      it = slot.erase(it);
      cb();
    } else {
      // persist: reschedule to next trigger point
      it->expire_tick = current_tick_ + it->interval_ticks;
      uint32_t new_slot = it->expire_tick % kWheelSize;
      if (new_slot != slot_idx) {
        // Move to new slot
        wheel_[new_slot].splice(wheel_[new_slot].end(), slot, it++);
        id_map_[id] = {new_slot, std::prev(wheel_[new_slot].end())};
      } else {
        ++it;
      }
      cb();
    }
  }
}

void TimerWheel::ForwardMs(uint64_t ms) {
  uint64_t ticks = ms / kTickMs;
  for (uint64_t i = 0; i < ticks; i++) {
    Tick();
  }
}

uint64_t TimerWheel::NowMs() const { return current_tick_ * kTickMs; }

}  // namespace example
