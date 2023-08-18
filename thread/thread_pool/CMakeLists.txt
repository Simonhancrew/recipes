cmake_minimum_required(VERSION 3.12)
project(ThreadPool)

find_package(Threads REQUIRED)

add_compile_options(-std=c++11 -Wall -g -Wextra)
add_executable(main example.cpp thread_pool.h)

target_include_directories(main PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../utils)
target_link_libraries(main PUBLIC Threads::Threads)
