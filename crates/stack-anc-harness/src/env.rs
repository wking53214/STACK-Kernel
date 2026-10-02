//! A snapshot of the machine a measurement ran on.
//!
//! Timing results only mean something next to the conditions they were
//! taken under: a loaded machine gives noisier samples and lower |t| for the
//! same leak. Every field is optional because `/proc` may be absent (non
//! Linux, sandbox), and a missing field never fails a measurement.

use serde::Serialize;
use std::io::Read;

/// Cap on bytes read from any `/proc` file. `/proc/cpuinfo` on a large host
/// is tens of KiB; this bound keeps a hostile or odd file from growing
/// memory without limit.
pub const MAX_PROC_READ_BYTES: u64 = 1 << 20;

/// Cap on the stored CPU model string, in bytes.
pub const MAX_CPU_MODEL_LEN: usize = 256;

/// Machine conditions at one moment.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Env {
    /// 1, 5 and 15 minute load averages from `/proc/loadavg`.
    pub load_avg: Option<[f64; 3]>,
    /// Logical CPUs available to this process
    /// (`std::thread::available_parallelism`).
    pub cpu_count: Option<usize>,
    /// First `model name` line of `/proc/cpuinfo`, truncated to
    /// [`MAX_CPU_MODEL_LEN`] bytes on a character boundary.
    pub cpu_model: Option<String>,
    /// `std::env::consts::ARCH`.
    pub arch: &'static str,
    /// `std::env::consts::OS`.
    pub os: &'static str,
}

fn read_bounded(path: &str) -> Option<String> {
    let f = std::fs::File::open(path).ok()?;
    let mut s = String::new();
    f.take(MAX_PROC_READ_BYTES).read_to_string(&mut s).ok()?;
    Some(s)
}

/// Parse the first three fields of `/proc/loadavg` text.
pub fn parse_loadavg(text: &str) -> Option<[f64; 3]> {
    let mut it = text.split_ascii_whitespace();
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    Some([a, b, c])
}

/// Find the first `model name` value in `/proc/cpuinfo` text.
pub fn parse_cpu_model(text: &str) -> Option<String> {
    let line = text.lines().find(|l| l.starts_with("model name"))?;
    let (_, value) = line.split_once(':')?;
    let value = value.trim();
    let mut end = value.len().min(MAX_CPU_MODEL_LEN);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    Some(value[..end].to_owned())
}

/// Load average, or `None` if `/proc/loadavg` is unreadable.
pub fn load_avg() -> Option<[f64; 3]> {
    parse_loadavg(&read_bounded("/proc/loadavg")?)
}

/// CPU model name, or `None` if `/proc/cpuinfo` is unreadable or has none.
pub fn cpu_model() -> Option<String> {
    parse_cpu_model(&read_bounded("/proc/cpuinfo")?)
}

/// Logical CPU count, or `None` if the OS will not say.
pub fn cpu_count() -> Option<usize> {
    std::thread::available_parallelism().ok().map(|n| n.get())
}

/// Take a snapshot of all of the above.
pub fn snapshot() -> Env {
    Env {
        load_avg: load_avg(),
        cpu_count: cpu_count(),
        cpu_model: cpu_model(),
        arch: std::env::consts::ARCH,
        os: std::env::consts::OS,
    }
}
