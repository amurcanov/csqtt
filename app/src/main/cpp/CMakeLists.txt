cmake_minimum_required(VERSION 3.22.1)
project("protect_shim" C)

add_library(protect_shim SHARED
    protect_shim.c
)

target_compile_options(protect_shim PRIVATE -Wall -Wextra -O2 -fPIC)

find_library(log-lib log)
target_link_libraries(protect_shim ${log-lib} dl)
