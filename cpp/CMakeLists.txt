cmake_minimum_required(VERSION 3.22)
project(stack_containment VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(stack_containment INTERFACE)
target_include_directories(stack_containment INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_options(stack_containment INTERFACE
    -fno-exceptions -fno-rtti -Wall -Wextra -Werror
    $<$<COMPILE_LANGUAGE:CXX>:-mavx2>
)

# Testing
find_package(Catch2 REQUIRED)
add_executable(stack_tests tests/tests_all_components.cpp)
target_link_libraries(stack_tests PRIVATE Catch2::Catch2WithMain stack_containment atomic)

add_executable(stack_production_hardened tests/tests_production_hardened.cpp)
target_link_libraries(stack_production_hardened PRIVATE Catch2::Catch2WithMain stack_containment atomic)

enable_testing()
add_test(NAME STACKTests COMMAND stack_tests)
add_test(NAME STACKProductionHardened COMMAND stack_production_hardened)
