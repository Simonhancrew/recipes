target("utils")
  set_kind("static")
  add_files("*.cc")
  add_files("*.cpp")
  add_includedirs("$(projectdir)")
