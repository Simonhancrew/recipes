add_requires("openssl")
add_rules("mode.release", "mode.debug")

option("use_boringssl")
  set_showmenu(true)
  set_category("option")
  set_description("Use boringssl instead of openssl")

option("boringssl_header")
  set_showmenu(true)
  set_category("option")
  set_description("Boringssl header path")

option("boringssl_lib")
  set_showmenu(true)
  set_category("option")
  set_description("Boringssl lib path")

target("aes_crypto")
  set_kind("binary")
  add_files("aes_crypto.cpp")
  set_languages("c++17")
  set_optimize("faster")
  set_warnings("all")
  if is_mode("debug") then 
    add_cflags("-g")
  end
  if has_config("use_boringssl") and get_config("use_boringssl") ~= "" then
    add_includedirs(get_config("boringssl_header"))
    add_linkdirs(get_config("boringssl_lib"))
    add_defines("USE_BORINGSSL")
    local lib_name = get_config("use_boringssl")
    add_links(lib_name)
  else
    add_packages("openssl")
  end
