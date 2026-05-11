add_requires("gtest")

target("timer_wheel_test")
  set_kind("binary")
  add_files("timer_wheel_test.cpp")
  add_deps("utils")
  add_packages("gtest")
  add_includedirs("$(projectdir)")
  set_default(false)
