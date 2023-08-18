// Created by SimonahanCrew at 2023/08/18

#pragma once

#include <functional>
#include <future>
#include <queue>

#include "construct_utils.h"

class ThreadPool {
 public:
  using TaskPackage = std::packaged_task<void()>;
  explicit ThreadPool(size_t num_threads);

  DISSALLOW_COPY_AND_ASSIGN(ThreadPool);
  DISSALLOW_MOVE_AND_ASSIGN(ThreadPool);

  template <typename F, typename... Args>
  auto Enqueue(F&& f, Args&&... args)
      -> std::future<typename std::result_of<F(Args...)>::type>;

  ~ThreadPool();

 private:
  std::vector<std::thread> workers_;
  // std::queue<TaskType> tasks_;
  std::queue<TaskPackage> tasks_;
  std::mutex queue_mutex_;
  std::condition_variable condition_;
  std::condition_variable condition_producers_;
  bool stop_;
};

inline ThreadPool::ThreadPool(size_t num_threads) : stop_(false) {
  for (size_t i = 0; i < num_threads; ++i) {
    workers_.emplace_back([this] {
      while (true) {
        TaskPackage task;
        {
          std::unique_lock<std::mutex> lock(this->queue_mutex_);
          this->condition_.wait(
              lock, [this] { return this->stop_ || !this->tasks_.empty(); });
          if (this->stop_ && this->tasks_.empty()) {
            return;
          }
          task = std::move(this->tasks_.front());
          this->tasks_.pop();
          if (tasks_.empty()) {
            // notify the destructor that the queue is empty
            condition_producers_.notify_one();
          }
        }
        task();
      }
    });
  }
}

template <class F, class... Args>
auto ThreadPool::Enqueue(F&& f, Args&&... args)
    -> std::future<typename std::result_of<F(Args...)>::type> {
  using return_type = typename std::result_of<F(Args...)>::type;
  // using return_type = typename std::invoke_result<F, Args...>::type;
  // using return_type = std::invoke_result_t<F, Args...>;
  std::packaged_task<return_type()> task(
      std::bind(std::forward<F>(f), std::forward<Args>(args)...));

  std::future<return_type> res = task.get_future();
  {
    std::unique_lock<std::mutex> lock(queue_mutex_);

    // don't allow enqueueing after stopping the pool
    if (stop_) {
      throw std::runtime_error("Enqueue on stopped ThreadPool");
    }

    tasks_.emplace(std::move(task));
  }
  condition_.notify_one();
  return res;
}

inline ThreadPool::~ThreadPool() {
  {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    condition_producers_.wait(lock, [this] { return tasks_.empty(); });
    stop_ = true;
  }
  condition_.notify_all();
  for (auto& worker : workers_) {
    worker.join();
  }
}
