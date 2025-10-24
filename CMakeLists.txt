cmake_minimum_required(VERSION 4.0)

set(TARGET_NAME cppCanTester)
set(OUTPUT_NAME can-tester)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_COLOR_DIAGNOSTICS ON)
set(CMAKE_CXX_STANDARD 17)

project(${TARGET_NAME})

add_executable(${TARGET_NAME})

set_target_properties(${TARGET_NAME} PROPERTIES RUNTIME_OUTPUT_NAME ${OUTPUT_NAME})

target_sources(${TARGET_NAME} PRIVATE main.cpp cxxopts.hpp)

set(Os_Build_Options
        $<$<COMPILE_LANGUAGE:CXX>: -Wno-pmf-conversions>
        -Wl,--gc-sections
        -fdata-sections
        -ffunction-sections
        -flto
)

target_compile_options(${TARGET_NAME} PRIVATE ${Os_Build_Options})
target_link_options(${TARGET_NAME} PRIVATE ${Os_Build_Options})

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(${TARGET_NAME} PRIVATE -O0 -g)
    target_link_options(${TARGET_NAME} PRIVATE -O0 -g)
    target_compile_definitions(${TARGET_NAME} PRIVATE DEBUG)
else ()
    target_compile_options(${TARGET_NAME} PRIVATE -Os)
    target_link_options(${TARGET_NAME} PRIVATE -Os -Wl,--strip-all)
endif ()

if (FALSE)
    set(ARM_TOOLCHAIN_PATH "${CMAKE_CURRENT_LIST_DIR}/Toolchains/arm-none-linux-gnueabihf")

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

if (FALSE)
    target_link_options(${TARGET_NAME} PRIVATE -static -static-libgcc -static-libstdc++)
endif ()
