fn main() {
    cc::Build::new()
        .cpp(true)
        .std("c++23")
        .flag("-O3")
        .flag("-march=native")
        .flag("-fno-exceptions")
        .flag("-fno-rtti")
        .file("src/ffi_wrapper.cpp")
        .include("../../cpp/include")
        .compile("tack_ffi");
    
    println!("cargo:rustc-link-lib=atomic");
    println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
}
