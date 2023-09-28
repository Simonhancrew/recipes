#pragma once

#define DISALLOW_COPY_AND_ASSIGN(type_name) \
  type_name(const type_name&) = delete;     \
  const type_name& operator=(const type_name&) = delete

#define DISALLOW_MOVE_AND_ASSIGN(type_name) \
  type_name(type_name&&) = delete;          \
  const type_name& operator=(type_name&&) = delete

// Usage
// switch(x) {
//   CASE_STRING(x)
// }
//
#define CASE_STRING(x) \
  case x:              \
    return #x;