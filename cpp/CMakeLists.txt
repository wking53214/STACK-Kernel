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

# FFI initialization red team (I-02): the wrapper's one-time initialization
# under 64 concurrent first callers, failure injection, and the no-implicit-
# seal rule. STACK_FFI_TESTING adds two counters to the wrapper; the shipped
# build (build.rs) never defines it.
add_executable(ffi_init_redteam tests/ffi_init_redteam.cpp ${STACK_FFI_WRAPPER})
target_compile_definitions(ffi_init_redteam PRIVATE STACK_FFI_TESTING=1)
target_link_libraries(ffi_init_redteam PRIVATE stack_containment atomic pthread)
add_test(NAME STACKRedteam_ffi_init COMMAND ffi_init_redteam)
set_tests_properties(STACKRedteam_ffi_init PROPERTIES TIMEOUT 300)

# The same program under ThreadSanitizer. A thread under the real seccomp
# allowlist cannot mmap, which the sanitizer runtime needs, so this build
# links an interposer that makes PR_SET_SECCOMP a no-op (STACK_FFI_NO_SECCOMP
# tells the program to skip its "thread is filtered" checks). This run checks
# the wrapper's synchronization, not the filter. ThreadSanitizer exits 66 on
# any report, which fails the test.
option(STACK_FFI_TSAN "Build and register the ThreadSanitizer run of the FFI init red team" ON)
if(STACK_FFI_TSAN)
    add_executable(ffi_init_redteam_tsan
        tests/ffi_init_redteam.cpp tests/ffi_no_seccomp_interpose.cpp ${STACK_FFI_WRAPPER})
    target_compile_definitions(ffi_init_redteam_tsan PRIVATE STACK_FFI_TESTING=1 STACK_FFI_NO_SECCOMP=1)
    target_compile_options(ffi_init_redteam_tsan PRIVATE -fsanitize=thread -g -O1)
    target_link_options(ffi_init_redteam_tsan PRIVATE -fsanitize=thread)
    target_link_libraries(ffi_init_redteam_tsan PRIVATE stack_containment atomic pthread)
    add_test(NAME STACKTsan_ffi_init COMMAND ffi_init_redteam_tsan)
    set_tests_properties(STACKTsan_ffi_init PROPERTIES TIMEOUT 600
        ENVIRONMENT "TSAN_OPTIONS=halt_on_error=0:exitcode=66")

    # The capability-change protocol (I-04: pending changes, the in-flight
    # counter and the condition variable the last transaction signals) under
    # ThreadSanitizer, with the same interposer and the same limits: this
    # checks the synchronization, not the filter. Only the [I-04] cases run:
    # the sustained-load revocation through the shipped wrapper, and the
    # latch-based host cases (a transaction held in flight, a change pending,
    # a new transaction refused, a timeout).
    add_executable(ffi_host_tests_tsan
        tests/ffi_host_tests.cpp tests/ffi_no_seccomp_interpose.cpp ${STACK_FFI_WRAPPER})
    target_compile_options(ffi_host_tests_tsan PRIVATE -fsanitize=thread -g -O1)
    target_link_options(ffi_host_tests_tsan PRIVATE -fsanitize=thread)
    target_link_libraries(ffi_host_tests_tsan PRIVATE Catch2::Catch2WithMain stack_containment atomic pthread)
    add_test(NAME STACKTsan_ffi_revocation COMMAND ffi_host_tests_tsan "[I-04]")

    add_executable(stack_tests_tsan tests/tests_all_components.cpp tests/ffi_no_seccomp_interpose.cpp)
    target_compile_options(stack_tests_tsan PRIVATE -fsanitize=thread -g -O1)
    target_link_options(stack_tests_tsan PRIVATE -fsanitize=thread)
    target_link_libraries(stack_tests_tsan PRIVATE Catch2::Catch2WithMain stack_containment atomic pthread)
    add_test(NAME STACKTsan_capability_change COMMAND stack_tests_tsan "[I-04]")
    set_tests_properties(STACKTsan_ffi_revocation STACKTsan_capability_change PROPERTIES TIMEOUT 600
        ENVIRONMENT "TSAN_OPTIONS=halt_on_error=0:exitcode=66")
endif()

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
