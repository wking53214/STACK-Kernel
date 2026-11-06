use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let cpp_include = PathBuf::from("../../cpp/include");
    // The C++ headers are compiled into the library, but cc only tracks the .cpp file.
    // Without this, a header edit (such as the seccomp allowlist) leaves a stale library.
    // Any rerun-if-changed line replaces Cargo's default "rerun on any package
    // file", so the wrapper source and this script must be listed too; without
    // them an edit to ffi_wrapper.cpp alone left a stale library (RACE-02).
    println!("cargo:rerun-if-changed=../../cpp/include");
    println!("cargo:rerun-if-changed=src/ffi_wrapper.cpp");
    println!("cargo:rerun-if-changed=build.rs");
    // The worker program is compiled from the same header; list its source too.
    println!("cargo:rerun-if-changed=../../cpp/worker/stack_worker.cpp");
    println!("cargo:rerun-if-env-changed=STACK_REQUIRE_STATIC_WORKER");

    cc::Build::new()
        .cpp(true)
        .std("c++23")
        .flag("-O3")
        .flag("-march=native")
        .flag("-fno-exceptions")
        .flag("-fno-rtti")
        .flag("-Wall")
        .flag("-Wextra")
        .include(cpp_include)
        .file("src/ffi_wrapper.cpp")
        .compile("stack_ffi");
    
    println!("cargo:rustc-link-lib=atomic");

    // The helper program SupervisedExecutor::RunWorker executes (RACE-02,
    // decision A). cc builds libraries, not programs, so the compiler it found
    // is run directly. The paths are exported to the crate for tests and
    // development only: a production kernel names its own worker by absolute
    // path in its configuration.
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let worker = build_worker(&out_dir, "stack_worker", &[]);
    let worker_test = build_worker(&out_dir, "stack_worker_test", &["-DSTACK_WORKER_TEST_KINDS=1"]);
    println!("cargo:rustc-env=STACK_WORKER_BUILD_PATH={}", worker.display());
    println!("cargo:rustc-env=STACK_WORKER_TEST_BUILD_PATH={}", worker_test.display());
}

/// Compiles cpp/worker/stack_worker.cpp to `out_dir/name`, statically linked
/// (no dynamic loader in the worker image). Falls back to a dynamic link only
/// when no static libc is installed, and says so as a build warning. A
/// dynamically linked worker is not covered by the image digest (the loader and
/// shared libraries run before the worker installs its seccomp filter), so a
/// build that must not fall back sets `STACK_REQUIRE_STATIC_WORKER` to any
/// value other than empty or `0`; the fallback is then a build error.
fn build_worker(out_dir: &Path, name: &str, defines: &[&str]) -> PathBuf {
    let target = out_dir.join(name);
    let compiler = cc::Build::new().cpp(true).get_compiler();
    let compile = |static_link: bool| -> bool {
        let mut cmd: Command = compiler.to_command();
        cmd.arg("-std=c++23").args(["-O2", "-fno-exceptions", "-fno-rtti", "-Wall", "-Wextra"]);
        cmd.arg("-I../../cpp/include");
        cmd.args(defines);
        if static_link {
            cmd.arg("-static");
        }
        cmd.arg("../../cpp/worker/stack_worker.cpp").arg("-o").arg(&target);
        matches!(cmd.status(), Ok(s) if s.success())
    };
    if !compile(true) {
        let required = std::env::var("STACK_REQUIRE_STATIC_WORKER").is_ok_and(|v| !v.is_empty() && v != "0");
        assert!(
            !required,
            "static link of {name} failed and STACK_REQUIRE_STATIC_WORKER is set, so a dynamically linked worker is refused (install a static libc, for example libc6-dev, or unset the variable)"
        );
        println!("cargo:warning=static link of {name} failed; using a dynamically linked worker");
        assert!(compile(false), "building the {name} helper program failed");
    }
    target
}
