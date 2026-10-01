//! Process and thread CPU time from `getrusage(2)`.
//!
//! Comparing thread CPU time to wall time over a run tells you whether the
//! measuring thread was descheduled (CPU time well below wall time), which
//! is a sign the timing samples are noisy.

use crate::error::HarnessError;
use serde::Serialize;
use std::time::Duration;

/// User and system CPU time consumed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CpuTime {
    /// Time spent in user mode.
    pub user: Duration,
    /// Time spent in the kernel on this caller's behalf.
    pub system: Duration,
}

impl CpuTime {
    /// User plus system time.
    pub fn total(&self) -> Duration {
        self.user.saturating_add(self.system)
    }

    /// Component-wise saturating difference `self - earlier`.
    pub fn since(&self, earlier: &CpuTime) -> CpuTime {
        CpuTime {
            user: self.user.saturating_sub(earlier.user),
            system: self.system.saturating_sub(earlier.system),
        }
    }
}

fn timeval_to_duration(tv: libc::timeval) -> Duration {
    let secs = u64::try_from(tv.tv_sec).unwrap_or(0);
    let micros = u32::try_from(tv.tv_usec).unwrap_or(0).min(999_999);
    Duration::new(secs, micros.saturating_mul(1_000))
}

#[allow(unsafe_code)]
fn rusage(who: libc::c_int, call: &'static str) -> Result<CpuTime, HarnessError> {
    let mut ru = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `ru` points to writable memory of exactly `size_of::<rusage>()`
    // bytes, which is what getrusage writes. It is zero-initialised, and
    // all-zero bytes are a valid `rusage` (a plain C struct of integers), so
    // `assume_init` is sound whether or not the call succeeded; we only read
    // it after checking the return code anyway.
    let (rc, ru) = unsafe {
        let rc = libc::getrusage(who, ru.as_mut_ptr());
        (rc, ru.assume_init())
    };
    if rc != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(HarnessError::Os { call, errno });
    }
    Ok(CpuTime {
        user: timeval_to_duration(ru.ru_utime),
        system: timeval_to_duration(ru.ru_stime),
    })
}

/// CPU time of the whole process (`RUSAGE_SELF`).
pub fn process_cpu_time() -> Result<CpuTime, HarnessError> {
    rusage(libc::RUSAGE_SELF, "getrusage(RUSAGE_SELF)")
}

/// CPU time of the calling thread (`RUSAGE_THREAD`, Linux only).
pub fn thread_cpu_time() -> Result<CpuTime, HarnessError> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        rusage(libc::RUSAGE_THREAD, "getrusage(RUSAGE_THREAD)")
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        Err(HarnessError::Unsupported("RUSAGE_THREAD"))
    }
}
