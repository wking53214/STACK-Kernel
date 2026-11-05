cmake_minimum_required(VERSION 3.22)
project(stack_containment VERSION 1.0.0 LANGUAGES C CXX)

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

# The worker program SupervisedExecutor::RunWorker executes (RACE-02, decision
# A): stack_worker is the shipped build (kinds 0 to 6), stack_worker_test adds
# kinds that misbehave on purpose and exists for the tests only. Both are
# linked statically: the image has no dynamic loader and no environment hooks.
add_executable(stack_worker worker/stack_worker.cpp)
target_link_libraries(stack_worker PRIVATE stack_containment)
target_link_options(stack_worker PRIVATE -static)
add_executable(stack_worker_test worker/stack_worker.cpp)
target_compile_definitions(stack_worker_test PRIVATE STACK_WORKER_TEST_KINDS=1)
target_link_libraries(stack_worker_test PRIVATE stack_containment)
target_link_options(stack_worker_test PRIVATE -static)

add_executable(stack_worker_exec_tests tests/worker_exec_tests.cpp)
target_compile_definitions(stack_worker_exec_tests PRIVATE
    STACK_WORKER_PATH="$<TARGET_FILE:stack_worker>"
    STACK_WORKER_TEST_PATH="$<TARGET_FILE:stack_worker_test>")
target_link_libraries(stack_worker_exec_tests PRIVATE Catch2::Catch2WithMain stack_containment atomic)
add_dependencies(stack_worker_exec_tests stack_worker stack_worker_test)

# Bounded reap (R2-K-12): built with STACK_SUPERVISED_TESTING, a compile-time
# seam that suppresses the supervisor's SIGKILL so TerminationUnconfirmed can
# be produced. The seam does not exist in any other target.
add_executable(stack_worker_reap_tests tests/worker_reap_tests.cpp)
target_compile_definitions(stack_worker_reap_tests PRIVATE
    STACK_SUPERVISED_TESTING=1
    STACK_WORKER_PATH="$<TARGET_FILE:stack_worker>"
    STACK_WORKER_TEST_PATH="$<TARGET_FILE:stack_worker_test>")
target_link_libraries(stack_worker_reap_tests PRIVATE Catch2::Catch2WithMain stack_containment atomic)
add_dependencies(stack_worker_reap_tests stack_worker stack_worker_test)

# The waitpid fallback path (no pidfd) with a late-observed deadline: libc
# kill, waitpid and syscall are interposed by the program itself, so no test
# hook exists in the header.
add_executable(stack_supervised_fallback_tests tests/supervised_fallback_tests.cpp)
target_link_libraries(stack_supervised_fallback_tests PRIVATE stack_containment atomic ${CMAKE_DL_LIBS})
add_test(NAME STACKSupervisedFallback COMMAND stack_supervised_fallback_tests)
set_tests_properties(STACKSupervisedFallback PROPERTIES TIMEOUT 120)

# The pid-reuse property without root (kill, waitpid, waitid and pidfd_send_signal
# are interposed by the program itself and every call after a "reaped
# elsewhere" is recorded). Needs the kill-hook seam; no label, runs everywhere.
add_executable(stack_pid_reuse_interposed_tests tests/pid_reuse_interposed_tests.cpp)
target_compile_definitions(stack_pid_reuse_interposed_tests PRIVATE
    STACK_SUPERVISED_TESTING=1
    STACK_WORKER_PATH="$<TARGET_FILE:stack_worker>")
target_link_libraries(stack_pid_reuse_interposed_tests PRIVATE stack_containment atomic ${CMAKE_DL_LIBS})
add_dependencies(stack_pid_reuse_interposed_tests stack_worker)
add_test(NAME STACKPidReuseInterposedRunning COMMAND stack_pid_reuse_interposed_tests running)
add_test(NAME STACKPidReuseInterposedTracked COMMAND stack_pid_reuse_interposed_tests tracked)
set_tests_properties(STACKPidReuseInterposedRunning STACKPidReuseInterposedTracked PROPERTIES TIMEOUT 120)

# The shipped FFI host (crates/stack-ffi/src/ffi_wrapper.cpp) through its C
# entry points: the same object, parameters and calibration a Rust caller gets.
set(STACK_FFI_WRAPPER ${CMAKE_CURRENT_SOURCE_DIR}/../crates/stack-ffi/src/ffi_wrapper.cpp)
add_executable(stack_ffi_tests tests/ffi_host_tests.cpp ${STACK_FFI_WRAPPER})
target_link_libraries(stack_ffi_tests PRIVATE Catch2::Catch2WithMain stack_containment atomic pthread)

# The shipped wrapper as a static library, for a caller that is not C++ (R-1): the C caller
# below is compiled as C and links only this archive and the worker's path.
add_library(stack_ffi_static STATIC ${STACK_FFI_WRAPPER})
target_link_libraries(stack_ffi_static PRIVATE stack_containment PUBLIC atomic pthread)
add_executable(ffi_c_caller tests/ffi_c_caller.c)
set_target_properties(ffi_c_caller PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON LINKER_LANGUAGE CXX)
target_compile_options(ffi_c_caller PRIVATE -Wall -Wextra -Werror)
target_compile_definitions(ffi_c_caller PRIVATE STACK_WORKER_PATH="$<TARGET_FILE:stack_worker>")
target_link_libraries(ffi_c_caller PRIVATE stack_ffi_static)
add_dependencies(ffi_c_caller stack_worker)

# The authorized entry points (D2-A) called directly from C: zero digest refused,
# a legitimate digest runs, a made-up non-zero digest is accepted (the pinned
# non-guarantee), governance still enforced.
add_executable(ffi_authorized_caller tests/ffi_authorized_caller.c)
set_target_properties(ffi_authorized_caller PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON LINKER_LANGUAGE CXX)
target_compile_options(ffi_authorized_caller PRIVATE -Wall -Wextra -Werror)
target_compile_definitions(ffi_authorized_caller PRIVATE STACK_WORKER_PATH="$<TARGET_FILE:stack_worker>")
target_link_libraries(ffi_authorized_caller PRIVATE stack_ffi_static)
add_dependencies(ffi_authorized_caller stack_worker)

# Governed supervised runs through the shipped wrapper (R2-K-13): governance
# before spawn, one audit event per outcome, refunds, revocation. Built with
# STACK_SUPERVISED_TESTING for the ineffective-kill seam (inert until used).
add_executable(ffi_supervised_tests tests/ffi_supervised_tests.cpp ${STACK_FFI_WRAPPER})
target_compile_definitions(ffi_supervised_tests PRIVATE
    STACK_SUPERVISED_TESTING=1
    STACK_WORKER_PATH="$<TARGET_FILE:stack_worker>")
target_link_libraries(ffi_supervised_tests PRIVATE Catch2::Catch2WithMain stack_containment atomic pthread)
add_dependencies(ffi_supervised_tests stack_worker)

# Worker image trust (R2-K-21): symlink, mode, NO_NEW_PRIVS and digest pin.
# probe_nnp is a test-only image that installs no filter and reports whether
# NO_NEW_PRIVS was already set. STACK_SUPERVISED_TESTING enables the swap seam.
add_executable(probe_nnp tests/probe_nnp.cpp)
target_link_libraries(probe_nnp PRIVATE stack_containment)
target_link_options(probe_nnp PRIVATE -static)
add_executable(stack_worker_image_tests tests/worker_image_tests.cpp)
target_compile_definitions(stack_worker_image_tests PRIVATE
    STACK_SUPERVISED_TESTING=1
    STACK_WORKER_PATH="$<TARGET_FILE:stack_worker>"
    STACK_WORKER_TEST_PATH="$<TARGET_FILE:stack_worker_test>"
    STACK_PROBE_NNP_PATH="$<TARGET_FILE:probe_nnp>")
target_link_libraries(stack_worker_image_tests PRIVATE Catch2::Catch2WithMain stack_containment atomic)
add_dependencies(stack_worker_image_tests stack_worker stack_worker_test probe_nnp)

enable_testing()
add_test(NAME STACKTests COMMAND stack_tests)
add_test(NAME STACKProductionHardened COMMAND stack_production_hardened)
add_test(NAME STACKSupervisedExec COMMAND stack_supervised_exec_tests)
set_tests_properties(STACKSupervisedExec PROPERTIES TIMEOUT 300)
add_test(NAME STACKWorkerExec COMMAND stack_worker_exec_tests)
set_tests_properties(STACKWorkerExec PROPERTIES TIMEOUT 300)
add_test(NAME STACKWorkerImage COMMAND stack_worker_image_tests)
set_tests_properties(STACKWorkerImage PROPERTIES TIMEOUT 300)
# The two pid-reuse cases write /proc/sys/kernel/ns_last_pid and so need
# CAP_SYS_ADMIN. They are a separate ctest entry with the label "needs-root",
# root-only and not run in CI (CI runs ctest -LE needs-root; the property is
# checked there by STACKPidReuseInterposed*). Never skipped: as an ordinary user
# they fail with an explanatory message.
add_test(NAME STACKWorkerReap COMMAND stack_worker_reap_tests "~[pid-reuse]")
set_tests_properties(STACKWorkerReap PROPERTIES TIMEOUT 300)
add_test(NAME STACKWorkerReapPidReuse COMMAND stack_worker_reap_tests "[pid-reuse]")
set_tests_properties(STACKWorkerReapPidReuse PROPERTIES TIMEOUT 300 LABELS needs-root)
add_test(NAME STACKFfiSupervised COMMAND ffi_supervised_tests)
set_tests_properties(STACKFfiSupervised PROPERTIES TIMEOUT 300)
add_test(NAME STACKFfiCCaller COMMAND ffi_c_caller)
set_tests_properties(STACKFfiCCaller PROPERTIES TIMEOUT 120)
add_test(NAME STACKFfiAuthorizedCaller COMMAND ffi_authorized_caller)
set_tests_properties(STACKFfiAuthorizedCaller PROPERTIES TIMEOUT 120)
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
