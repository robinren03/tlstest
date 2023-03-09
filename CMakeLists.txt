project(tlstest)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS   "-no-pie")  
set(CMAKE_C_FLAGS   "-no-pie")  
cmake_minimum_required(VERSION 3.3)

add_subdirectory(src)
