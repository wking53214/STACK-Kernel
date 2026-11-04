use std::path::PathBuf;

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
}
