//! R2-K-22: the ungoverned legacy supervised run must not be reachable from
//! safe Rust. `supervised_run` forks the caller and makes no capability or
//! rate-limit check, so the only safe public entry that runs a supervised
//! payload is `supervised_run_governed`.
//!
//! Compile-fail is covered by the doc test on `supervised_run` (E0133). This
//! file is the source-level guard, in the style of the stack-authority
//! no-signing test: it reads `src/lib.rs` and fails if a safe public function
//! can reach the ungoverned C symbol.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const LIB: &str = include_str!("../src/lib.rs");

/// The lines of the non-test part of the crate source.
fn non_test_source() -> &'static str {
    LIB.split("#[cfg(test)]").next().expect("source before the test module")
}

#[test]
fn the_legacy_supervised_run_is_an_unsafe_fn() {
    let src = non_test_source();
    assert!(
        !src.contains("pub fn supervised_run("),
        "supervised_run is a safe public function again: it reaches the ungoverned C entry"
    );
    assert!(
        src.contains("pub unsafe fn supervised_run("),
        "expected `pub unsafe fn supervised_run(` in src/lib.rs"
    );
}

#[test]
fn no_safe_public_function_calls_the_ungoverned_c_symbol() {
    // Walk the source function by function: a `pub fn` (safe) whose body
    // mentions `stack_supervised_run(` (the ungoverned symbol, not
    // `stack_supervised_run_governed(`) is a safe path to it.
    // The `extern "C"` block is skipped: its items are unsafe to call by
    // construction, which is exactly the property wanted of the legacy symbol.
    let src = non_test_source();
    let extern_start = src.find("extern \"C\" {").expect("extern block");
    let extern_end = extern_start + src[extern_start..].find("\n}\n").expect("end of extern block");
    let mut safe_part = String::from(&src[..extern_start]);
    safe_part.push_str(&src[extern_end..]);
    let mut offenders = Vec::new();
    let mut rest = safe_part.as_str();
    while let Some(at) = rest.find("pub fn ") {
        let after = &rest[at + "pub fn ".len()..];
        let name_end = after.find('(').expect("fn name");
        let name = &after[..name_end];
        // The body runs to the next top-level item; the next "\npub " or "\n}" at column 0.
        let body_end = after.find("\npub ").or_else(|| after.find("\n}\n")).unwrap_or(after.len());
        let body = &after[..body_end];
        if body.contains("stack_supervised_run(") {
            offenders.push(name.to_owned());
        }
        rest = &after[name_end..];
    }
    assert!(offenders.is_empty(), "safe public functions reach stack_supervised_run: {offenders:?}");
}

#[test]
fn the_governed_entry_is_the_one_safe_supervised_run() {
    let src = non_test_source();
    assert!(src.contains("pub fn supervised_run_governed("));
    // Exactly one place calls the governed C symbol from a safe function.
    assert_eq!(src.matches("stack_supervised_run_governed(").count(), 2, "declaration plus one call");
}

/// R-1, lifetime: the host is constructed once and lives for the process. There is no
/// teardown, so there is no exported symbol and no public Rust function whose name says
/// shutdown, teardown, destroy, finalize, deinit, uninit, reset, free, release or close.
/// If one is ever added, this test fails and ABI.md section 3 ("Lifetime") must change with it.
/// Behaviour that goes with the statement (a repeated init is idempotent and keeps the state)
/// is tested by cpp/tests/ffi_c_caller.c (ctest STACKFfiCCaller) and
/// cpp/tests/ffi_init_redteam.cpp (ctest STACKRedteam_ffi_init).
#[test]
fn the_host_has_no_teardown_entry_point() {
    const WRAPPER: &str = include_str!("../src/ffi_wrapper.cpp");
    const TEARDOWN_WORDS: [&str; 10] = [
        "shutdown", "teardown", "destroy", "finalize", "deinit", "uninit", "reset", "free", "release", "close",
    ];
    // Exported C symbols: definitions at column 0 inside the extern "C" block.
    let mut exported = Vec::new();
    for line in WRAPPER.lines() {
        for prefix in ["int ", "uint64_t ", "void "] {
            if let Some(rest) = line.strip_prefix(prefix) {
                if let Some(name) = rest.split('(').next() {
                    if name.starts_with("stack_") && rest.contains('(') {
                        exported.push(name.to_owned());
                    }
                }
            }
        }
    }
    assert!(exported.iter().any(|n| n == "stack_host_initialize"), "parsed the wrong thing: {exported:?}");
    assert!(exported.len() >= 15, "parsed too few symbols: {exported:?}");
    let src = non_test_source();
    let mut rust_names = Vec::new();
    for line in src.lines() {
        if let Some(rest) = line.strip_prefix("pub fn ") {
            if let Some(name) = rest.split(['(', '<']).next() {
                rust_names.push(name.to_owned());
            }
        }
    }
    for name in exported.iter().chain(rust_names.iter()) {
        for word in TEARDOWN_WORDS {
            assert!(!name.contains(word), "`{name}` looks like a teardown entry point (`{word}`): the host has none");
        }
    }
}
