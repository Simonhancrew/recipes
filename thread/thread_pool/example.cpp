#include <algorithm>
#include <cstring>
#include <iostream>
#include <thread>

#include "thread_pool.h"

// Created by Simonhancrew on 2023/08/18

const int kThreadCnt = 3;

using FutureRes = std::future<int>;

int main() {
  ThreadPool pool(kThreadCnt);
  std::vector<FutureRes> res;
  res.reserve(kThreadCnt);
  for (int i = 0; i < kThreadCnt; i++) {
    res.emplace_back(pool.Enqueue([i] {
      std::cout << i << "--->\n";
      std::this_thread::sleep_for(std::chrono::seconds(1));
      return i;
    }));
  }
  for (int i = 0; i < kThreadCnt; i++) {
    std::cout << res[i].get() << '\n';
  }
  return 0;
}
