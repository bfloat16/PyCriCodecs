cmake_minimum_required(VERSION 3.10)
project(hca_decryptor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(pybind11)
set(PYTHON_EXECUTABLE "C:/SDK/uv/python/cpython-3.12.11-windows-x86_64-none/python.exe")
set(PYTHON_INCLUDE_DIR "C:/SDK/uv/python/cpython-3.12.11-windows-x86_64-none/include")

pybind11_add_module(hcadecrypt hca_decryptor.cpp)