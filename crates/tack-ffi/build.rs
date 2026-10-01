use std::path::PathBuf;

fn main() {
    let cpp_include = PathBuf::from("../../cpp/include");
    
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
        .compile("tack_ffi");
    
    println!("cargo:rustc-link-lib=atomic");
}
