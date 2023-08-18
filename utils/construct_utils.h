#pragma once

#define DISSALLOW_COPY_AND_ASSIGN(type) \
  type(const type&) = delete;           \
  type& operator=(const type&) = delete

#define DISSALLOW_MOVE_AND_ASSIGN(type) \
  type(type&&) = delete;                \
  type& operator=(type&&) = delete
