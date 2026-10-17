use std::path::PathBuf;

fn main() {
    let cpp_include = PathBuf::from("../../cpp/include");
    // The C++ headers are compiled into the library, but cc only tracks the .cpp file.
    // Without this, a header edit (such as the seccomp allowlist) leaves a stale library.
    println!("cargo:rerun-if-changed=../../cpp/include");
    
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
