cmake_minimum_required(VERSION 3.20)
project(hca_decryptor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(pybind11)

pybind11_add_module(hcadecrypt hca_decryptor.cpp)