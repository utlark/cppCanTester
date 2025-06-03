cmake_minimum_required(VERSION 3.31)
project(cppCanTester)

set(CMAKE_CXX_STANDARD 17)

if (TRUE)
    set(ARM_TOOLCHAIN_PATH "/home/dash/Work/CLion/CXX/cppSaut/Toolchains/arm-none-linux-gnueabihf")

    set(CMAKE_C_COMPILER ${ARM_TOOLCHAIN_PATH}/bin/arm-none-linux-gnueabihf-gcc)
    set(CMAKE_CXX_COMPILER ${ARM_TOOLCHAIN_PATH}/bin/arm-none-linux-gnueabihf-g++)
    set(CMAKE_OBJCOPY ${ARM_TOOLCHAIN_PATH}/bin/arm-none-linux-gnueabihf-objcopy)
    set(CMAKE_OBJDUMP ${ARM_TOOLCHAIN_PATH}/bin/arm-none-linux-gnueabihf-objdump)

    set(CMAKE_C_COMPILER_WORKS 1)
    set(CMAKE_CXX_COMPILER_WORKS 1)

    set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
endif ()

add_executable(cppCanTester main.cpp)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(cppCanTester PRIVATE -O0 -g)
    target_link_options(cppCanTester PRIVATE -O0 -g)
    target_compile_definitions(cppCanTester PRIVATE DEBUG)
else ()
    target_compile_options(cppCanTester PRIVATE -Os)
    target_link_options(cppCanTester PRIVATE -Os -Wl,--strip-all)
endif ()

if (FALSE)
    target_link_options(cppCanTester PRIVATE -static)
endif ()
