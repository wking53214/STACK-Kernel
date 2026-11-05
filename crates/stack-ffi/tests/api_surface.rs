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
