add_requires("openssl")

target("aes_crypto")
  set_kind("binary")
  add_files("aes_crypto.cpp")
  add_packages("openssl")
