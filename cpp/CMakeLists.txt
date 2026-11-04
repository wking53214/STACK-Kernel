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

# Supervised execution: every hostile payload runs in a killed-at-deadline child.
add_executable(stack_supervised_exec_tests tests/supervised_exec_tests.cpp)
target_link_libraries(stack_supervised_exec_tests PRIVATE Catch2::Catch2WithMain stack_containment atomic)

# The shipped FFI host (crates/stack-ffi/src/ffi_wrapper.cpp) through its C
# entry points: the same object, parameters and calibration a Rust caller gets.
set(STACK_FFI_WRAPPER ${CMAKE_CURRENT_SOURCE_DIR}/../crates/stack-ffi/src/ffi_wrapper.cpp)
add_executable(stack_ffi_tests tests/ffi_host_tests.cpp ${STACK_FFI_WRAPPER})
target_link_libraries(stack_ffi_tests PRIVATE Catch2::Catch2WithMain stack_containment atomic pthread)

enable_testing()
add_test(NAME STACKTests COMMAND stack_tests)
add_test(NAME STACKProductionHardened COMMAND stack_production_hardened)
add_test(NAME STACKSupervisedExec COMMAND stack_supervised_exec_tests)
set_tests_properties(STACKSupervisedExec PROPERTIES TIMEOUT 300)
add_test(NAME STACKFfiHost COMMAND stack_ffi_tests)
set_tests_properties(STACKFfiHost PROPERTIES TIMEOUT 300)

# Red-team programs: plain main() executables that exit non-zero on failure.
# Built with the same -Werror flags as everything else.
set(STACK_REDTEAM_TESTS
    layer2_redteam
    layer4_redteam
    layer5_redteam
    layer6_redteam
    layer6_wraparound_redteam
    layer8_redteam
    p3_audit_trail_signing_redteam
    p3_per_domain_rate_limiting_redteam
)
foreach(redteam IN LISTS STACK_REDTEAM_TESTS)
    add_executable(${redteam} tests/${redteam}.cpp)
    target_link_libraries(${redteam} PRIVATE stack_containment atomic pthread)
    add_test(NAME STACKRedteam_${redteam} COMMAND ${redteam})
    set_tests_properties(STACKRedteam_${redteam} PROPERTIES TIMEOUT 300)
endforeach()
