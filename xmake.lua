set_project("recipes")

if is_mode("release") then
    set_optimize("faster")
    set_strip("all")
elseif is_mode("debug") then
    set_symbols("debug")
    set_optimize("none")
end

set_languages("gnu90", "c++17")
set_warnings("all")
set_exceptions("no-cxx")

includes("utils")
