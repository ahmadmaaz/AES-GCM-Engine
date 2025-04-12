cmake_minimum_required(VERSION 3.25)
project(AES_Paralelized)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_CXX_STANDARD_REQUIRED True)

# Enable AES-NI Intrinsics (SSE4.1, AES-NI)
if(MSVC)
    add_compile_options(/arch:AVX2)  # For MSVC
else()
    add_compile_options(-maes -msse4.1)  # For GCC/Clang
endif()

add_executable(
        AES.cpp
        Ghash.cpp
        Utils.cpp
)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes -mpclmul -msse2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")

if(CMAKE_BUILD_TYPE MATCHES Release)
    add_compile_options(-O3)  # Enable optimizations
endif()