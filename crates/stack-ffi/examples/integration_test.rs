use stack_ffi::{host_initialize_and_seal, host_set_capabilities, read_ticks};

fn main() {
    println!("≡TACK C++/Rust Integration Test");
    
    // Initialize the host
    if let Err(e) = host_initialize_and_seal() {
        eprintln!("Failed to initialize host: {:?}", e);
        return;
    }
    println!("✓ Host initialized and sealed");
    
    // Set active capabilities
    if let Err(e) = host_set_capabilities(0xFF, 0, 0, 0) {
        eprintln!("Failed to set capabilities: {:?}", e);
        return;
    }
    println!("✓ Capabilities set");
    
    // Read tick counter
    let t1 = read_ticks();
    let t2 = read_ticks();
    println!("✓ Tick counter: {} → {}", t1, t2);
}
