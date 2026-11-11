//! Four-connection loopback timing measurement for the token comparison victims.
//!
//! A server on 127.0.0.1 checks each 32-byte candidate against a secret with
//! either the leaky comparison (`--victim leaky`, the control that should show
//! a timing gap) or the constant-time comparison (`--victim ct`, which should
//! show none). A client sends two classes of candidate over several connections
//! in random order and records each round trip:
//!   class A: 31 leading bytes correct, so the leaky check runs longest;
//!   class B: the first byte wrong, so the leaky check stops at once.
//! Each comparison is timed on the server with Instant, so the figures are
//! server-side comparison times, not client round trips.
//! The gap between the classes' trimmed means is compared with a Welch t, and
//! the number of requests per class needed to reach |t| of 4.5 is estimated.
//! This measures loopback only, on the machine it runs on.
//!
//! usage: loopback_four_conn [--victim leaky|ct] [--connections N]
//!          [--per-class N] [--runs N] [--seed N] [--out FILE]

// A measurement tool, not production code: a socket or thread that fails during
// setup should stop the run with a message, as the workspace's tests do.
#![allow(clippy::expect_used, clippy::panic)]

use stack_anc_harness::victim::{ct_validate, leaky_validate, TOKEN_LEN};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Instant;

struct SplitMix(u64);
impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

struct RunResult {
    n_per_class: usize,
    median_a_ns: f64,
    median_b_ns: f64,
    gap_ns: f64,
    t: f64,
    n_needed_per_class: f64,
}

fn arg<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> T {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn arg_str(args: &[String], name: &str, default: &str) -> String {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn trimmed_mean_var(sorted: &[f64]) -> (usize, f64, f64) {
    let n = sorted.len();
    let mid = &sorted[n / 4..n - n / 4];
    let m = mid.len() as f64;
    let mean = mid.iter().sum::<f64>() / m;
    let var = mid.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / (m - 1.0);
    (mid.len(), mean, var)
}

fn run_once(connections: usize, per_class: usize, leaky: bool, seed: u64) -> RunResult {
    let expected = [0x5au8; TOKEN_LEN];
    let mut cand_a = expected;
    cand_a[TOKEN_LEN - 1] ^= 0xff; // 31 bytes match before the mismatch
    let mut cand_b = expected;
    cand_b[0] ^= 0xff; // mismatch at the first byte

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let addr = listener.local_addr().expect("local addr");

    // The server times only the comparison call, so loopback round-trip noise
    // does not swamp the few tens of nanoseconds the comparison takes.
    // A request is class A when its first byte matches the secret.
    let server = thread::spawn(move || {
        let mut handles = Vec::new();
        for _ in 0..connections {
            let (mut s, _) = listener.accept().expect("accept");
            s.set_nodelay(true).ok();
            handles.push(thread::spawn(move || {
                let mut buf = [0u8; TOKEN_LEN];
                let mut times: Vec<(bool, f64)> = Vec::new();
                while s.read_exact(&mut buf).is_ok() {
                    let is_a = buf[0] == expected[0];
                    let t0 = Instant::now();
                    let ok = if leaky {
                        leaky_validate(&expected, &buf)
                    } else {
                        ct_validate(&expected, &buf)
                    };
                    let ns = t0.elapsed().as_nanos() as f64;
                    times.push((is_a, ns));
                    if s.write_all(&[ok as u8]).is_err() {
                        break;
                    }
                }
                times
            }));
        }
        let mut all = Vec::new();
        for h in handles {
            all.extend(h.join().expect("server connection thread"));
        }
        all
    });

    let total = per_class * 2;
    let mut rng = SplitMix(seed);
    let mut classes: Vec<bool> = (0..total).map(|i| i < per_class).collect();
    for i in (1..total).rev() {
        let j = (rng.next() % (i as u64 + 1)) as usize;
        classes.swap(i, j);
    }
    let mut per_conn: Vec<Vec<bool>> = vec![Vec::new(); connections];
    for (i, c) in classes.into_iter().enumerate() {
        per_conn[i % connections].push(c);
    }

    let clients: Vec<_> = per_conn
        .into_iter()
        .map(|sched| {
            thread::spawn(move || {
                let mut s = TcpStream::connect(addr).expect("connect loopback");
                s.set_nodelay(true).ok();
                let mut reply = [0u8; 1];
                for is_a in sched {
                    let msg = if is_a { cand_a } else { cand_b };
                    s.write_all(&msg).expect("write");
                    s.read_exact(&mut reply).expect("read");
                }
            })
        })
        .collect();
    for c in clients {
        c.join().expect("client thread");
    }
    let timings = server.join().expect("server thread");
    let mut a: Vec<f64> = timings.iter().filter(|t| t.0).map(|t| t.1).collect();
    let mut b: Vec<f64> = timings.iter().filter(|t| !t.0).map(|t| t.1).collect();

    a.sort_by(|x, y| x.partial_cmp(y).expect("finite"));
    b.sort_by(|x, y| x.partial_cmp(y).expect("finite"));
    let median_a = a[a.len() / 2];
    let median_b = b[b.len() / 2];
    let (na, ma, va) = trimmed_mean_var(&a);
    let (nb, mb, vb) = trimmed_mean_var(&b);
    let gap = ma - mb;
    let t = gap / (va / na as f64 + vb / nb as f64).sqrt();
    let n_needed = if gap == 0.0 {
        f64::INFINITY
    } else {
        4.5 * 4.5 * (va + vb) / (gap * gap)
    };
    RunResult {
        n_per_class: per_class,
        median_a_ns: median_a,
        median_b_ns: median_b,
        gap_ns: gap,
        t,
        n_needed_per_class: n_needed,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let victim = arg_str(&args, "--victim", "leaky");
    let connections: usize = arg(&args, "--connections", 4);
    let per_class: usize = arg(&args, "--per-class", 200_000);
    let runs: usize = arg(&args, "--runs", 3);
    let seed: u64 = arg(&args, "--seed", 1);
    let out = arg_str(&args, "--out", "");
    let leaky = match victim.as_str() {
        "leaky" => true,
        "ct" => false,
        other => panic!("--victim must be leaky or ct, got {other}"),
    };

    let mut results = Vec::new();
    for r in 0..runs {
        let res = run_once(connections, per_class, leaky, seed.wrapping_add(r as u64));
        eprintln!(
            "run {r}: median A {:.0} ns, median B {:.0} ns, gap {:+.2} ns, t {:+.2}, n needed per class {:.0}",
            res.median_a_ns, res.median_b_ns, res.gap_ns, res.t, res.n_needed_per_class
        );
        results.push(res);
    }

    let gaps: Vec<f64> = results.iter().map(|r| r.gap_ns).collect();
    let mean_gap = gaps.iter().sum::<f64>() / gaps.len() as f64;
    let spread = (gaps.iter().map(|g| (g - mean_gap).powi(2)).sum::<f64>()
        / (gaps.len().max(2) - 1) as f64)
        .sqrt();
    let runs_json: Vec<String> = results
        .iter()
        .map(|r| {
            format!(
                "{{\"n_per_class\":{},\"median_a_ns\":{:.1},\"median_b_ns\":{:.1},\"gap_ns\":{:.3},\"t\":{:.3},\"n_needed_per_class\":{:.1}}}",
                r.n_per_class, r.median_a_ns, r.median_b_ns, r.gap_ns, r.t, r.n_needed_per_class
            )
        })
        .collect();
    let json = format!(
        "{{\"victim\":\"{victim}\",\"connections\":{connections},\"per_class\":{per_class},\"seed\":{seed},\"mean_gap_ns\":{mean_gap:.3},\"gap_sd_across_runs_ns\":{spread:.3},\"runs\":[{}]}}\n",
        runs_json.join(",")
    );
    if out.is_empty() {
        print!("{json}");
    } else {
        std::fs::write(&out, json).expect("write output");
        eprintln!("wrote {out}");
    }
}
