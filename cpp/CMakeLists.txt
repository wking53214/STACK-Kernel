cmake_minimum_required(VERSION 3.22)
project(tack_containment_stack VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(tack_containment INTERFACE)
target_include_directories(tack_containment INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_options(tack_containment INTERFACE
    -fno-exceptions -fno-rtti -Wall -Wextra -Werror
    $<$<COMPILE_LANGUAGE:CXX>:-mavx2>
)

# Testing
find_package(Catch2 REQUIRED)
add_executable(tack_tests tests/tests_all_components.cpp)
target_link_libraries(tack_tests PRIVATE Catch2::Catch2WithMain tack_containment atomic)

add_executable(tack_production_hardened tests/tests_production_hardened.cpp)
target_link_libraries(tack_production_hardened PRIVATE Catch2::Catch2WithMain tack_containment atomic)

enable_testing()
add_test(NAME TACKTests COMMAND tack_tests)
add_test(NAME TACKProductionHardened COMMAND tack_production_hardened)
