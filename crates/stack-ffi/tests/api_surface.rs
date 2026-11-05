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

/// The public functions of the source with their full signature text (up to the
/// opening brace) and body (to the next top-level item), split into safe and unsafe.
fn pub_functions(src: &str) -> Vec<(String, bool, String, String)> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(at) = rest.find("\npub ") {
        let after = &rest[at + 1..];
        let line_end = after.find('\n').unwrap_or(after.len());
        let head = &after[..line_end];
        let (is_fn, is_unsafe) = (head.starts_with("pub fn "), head.starts_with("pub unsafe fn "));
        let body_end = after[1..].find("\npub ").map_or(after.len(), |i| i + 1);
        let body_end = after[..body_end].rfind("\n}\n").map_or(body_end, |i| i + 3);
        if is_fn || is_unsafe {
            let name_start = head.find("fn ").expect("fn") + 3;
            let name: String = head[name_start..].chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            let signature_end = after.find(" {\n").unwrap_or(line_end);
            out.push((name, is_unsafe, after[..signature_end].to_owned(), after[..body_end].to_owned()));
        }
        rest = &after[1..];
    }
    out
}

/// D2-A: the safe governed entry points take the authorization; the raw ones are `unsafe fn`;
/// and no safe public function reaches a C symbol that takes no authorization.
#[test]
fn the_safe_governed_entry_points_take_an_authorized_action_and_the_raw_ones_are_unsafe() {
    let src = non_test_source();
    let fns = pub_functions(src);
    let find = |n: &str| fns.iter().find(|f| f.0 == n).unwrap_or_else(|| panic!("no pub fn {n}: {:?}", fns.iter().map(|f| &f.0).collect::<Vec<_>>()));

    for name in ["supervised_run_governed", "execute_governed_transaction"] {
        let (_, is_unsafe, signature, _) = find(name);
        assert!(!is_unsafe, "{name} must be safe");
        assert!(
            signature.contains("authorization: &AuthorizedAction"),
            "{name} must take `authorization: &AuthorizedAction`: {signature}"
        );
    }
    for name in ["supervised_run_governed_unauthorized", "execute_governed_transaction_unauthorized", "supervised_run"] {
        let (_, is_unsafe, signature, _) = find(name);
        assert!(*is_unsafe, "{name} must be an unsafe fn: {signature}");
        assert!(!signature.contains("AuthorizedAction"), "{name} is the raw path");
    }

    // Safe functions reach only the authorized C symbols for governed execution.
    let raw_symbols = [
        "stack_supervised_run(",
        "stack_supervised_run_governed(",
        "stack_execute_governed_transaction(",
    ];
    let mut offenders = Vec::new();
    for (name, is_unsafe, _, body) in &fns {
        if *is_unsafe {
            continue;
        }
        // The text of a safe function that is not an extern declaration.
        for sym in raw_symbols {
            if body.contains(sym) && !body.contains("extern \"C\"") {
                offenders.push(format!("{name} -> {sym}"));
            }
        }
    }
    assert!(offenders.is_empty(), "safe public functions reach a C symbol that takes no authorization: {offenders:?}");

    // The authorized symbols are called exactly once each from safe code, with the digest.
    for (name, sym) in [
        ("supervised_run_governed", "stack_supervised_run_authorized("),
        ("execute_governed_transaction", "stack_execute_governed_transaction_authorized("),
    ] {
        let (_, _, _, body) = find(name);
        assert!(body.contains(sym), "{name} must call {sym}");
        assert!(body.contains("cap_digest()"), "{name} must pass the capability digest");
    }
}

/// No safe public function takes a bare capability mask and runs a worker or a transaction:
/// the only items in the public surface that can start governed execution are the four above.
#[test]
fn only_the_named_functions_can_start_governed_execution() {
    let src = non_test_source();
    let mut starts = Vec::new();
    for (name, is_unsafe, _, body) in pub_functions(src) {
        let calls_c = ["stack_supervised_run", "stack_execute_governed_transaction"]
            .iter()
            .any(|s| body.contains(&format!("{s}(")) || body.contains(&format!("{s}_governed(")) || body.contains(&format!("{s}_authorized(")));
        if calls_c {
            starts.push((name, is_unsafe));
        }
    }
    starts.sort();
    assert_eq!(
        starts,
        vec![
            ("execute_governed_transaction".to_owned(), false),
            ("execute_governed_transaction_unauthorized".to_owned(), true),
            ("supervised_run".to_owned(), true),
            ("supervised_run_governed".to_owned(), false),
            ("supervised_run_governed_unauthorized".to_owned(), true),
        ]
    );
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
