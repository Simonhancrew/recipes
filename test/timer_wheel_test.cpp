#include "utils/timer_wheel.h"

#include <gtest/gtest.h>

using example::TimerWheel;

class TimerWheelTest : public ::testing::Test {
 protected:
  TimerWheel wheel_;
};

TEST_F(TimerWheelTest, OneShotFiresOnce) {
  int count = 0;
  wheel_.CreateTimer([&] { count++; }, 10, /*one_shot=*/true);

  wheel_.ForwardMs(10);
  EXPECT_EQ(count, 1);

  wheel_.ForwardMs(10);
  EXPECT_EQ(count, 1);  // should not fire again
}

TEST_F(TimerWheelTest, PersistFiresRepeatedly) {
  int count = 0;
  wheel_.CreateTimer([&] { count++; }, 50, /*one_shot=*/false);

  wheel_.ForwardMs(50);
  EXPECT_EQ(count, 1);

  wheel_.ForwardMs(50);
  EXPECT_EQ(count, 2);

  wheel_.ForwardMs(50);
  EXPECT_EQ(count, 3);
}

TEST_F(TimerWheelTest, CancelPreventsFireing) {
  int count = 0;
  auto id = wheel_.CreateTimer([&] { count++; }, 10, /*one_shot=*/false);

  wheel_.ForwardMs(10);
  EXPECT_EQ(count, 1);

  wheel_.Cancel(id);

  wheel_.ForwardMs(10);
  EXPECT_EQ(count, 1);  // cancelled, should not fire
}

TEST_F(TimerWheelTest, CancelNonExistentIdIsNoOp) {
  // Should not crash
  wheel_.Cancel(9999);
}

TEST_F(TimerWheelTest, MultipleTimersDifferentIntervals) {
  int count_a = 0, count_b = 0;
  wheel_.CreateTimer([&] { count_a++; }, 10, /*one_shot=*/false);
  wheel_.CreateTimer([&] { count_b++; }, 30, /*one_shot=*/false);

  wheel_.ForwardMs(30);
  EXPECT_EQ(count_a, 3);
  EXPECT_EQ(count_b, 1);
}

TEST_F(TimerWheelTest, NowMsTracksTime) {
  EXPECT_EQ(wheel_.NowMs(), 0u);
  wheel_.ForwardMs(100);
  EXPECT_EQ(wheel_.NowMs(), 100u);
}

TEST_F(TimerWheelTest, TimerWrapsAroundWheel) {
  // Timer with interval > kWheelSize (256ms) to test wrap-around
  int count = 0;
  wheel_.CreateTimer([&] { count++; }, 300, /*one_shot=*/true);

  wheel_.ForwardMs(299);
  EXPECT_EQ(count, 0);

  wheel_.ForwardMs(1);
  EXPECT_EQ(count, 1);
}
