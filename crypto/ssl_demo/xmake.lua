set_project("ssl_demo")

set_languages("c++17")

add_requires("openssl")

if is_mode("debug") then
    set_symbols("debug")
    set_optimize("none")
elseif is_mode("release") then
    set_symbols("hidden")
    set_optimize("fastest")
end

target("ssl_session")
    set_kind("static")
    add_files("src/ssl_session.cpp")
    add_packages("openssl")
    add_includedirs("$(projectdir)")

target("ssl_client")
    set_kind("binary")
    add_files("src/ssl_client.cpp")
    add_deps("ssl_session")
    add_includedirs("$(projectdir)")

target("ssl_server")
    set_kind("binary")
    add_files("src/ssl_server.cpp")
    add_deps("ssl_session")
    add_includedirs("$(projectdir)")
