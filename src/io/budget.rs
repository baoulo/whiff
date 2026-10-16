use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use super::SourceError;

/// Monotonic clock. `std::time::Instant` panics on `wasm32-unknown-unknown`,
/// so there the clock is absent and deadlines are not enforced.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
type Instant = std::time::Instant;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[allow(clippy::unnecessary_wraps)] // `None` on wasm32-unknown-unknown
fn now() -> Option<Instant> {
    Some(Instant::now())
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
struct Instant;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl std::ops::Add<Duration> for Instant {
    type Output = Instant;
    fn add(self, _: Duration) -> Instant {
        Instant
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn now() -> Option<Instant> {
    None
}

/// Resource limits shared by everything that reads one root input and its
/// embedded children. Cheap to clone (an `Arc`).
#[derive(Clone, Debug)]
pub struct Budget {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    read_limit: u64,
    read: AtomicU64,
    decompressed_limit: u64,
    decompressed: AtomicU64,
    file_deadline: Option<Instant>,
    /// The tighter of the file deadline and the current extractor's deadline.
    current_deadline: Mutex<Option<Instant>>,
    limits_hit: Mutex<Vec<&'static str>>,
}

impl Budget {
    /// A budget allowing `read_limit` bytes read, `decompressed_limit` bytes
    /// inflated, and finishing within `timeout`.
    pub fn new(read_limit: u64, decompressed_limit: u64, timeout: Option<Duration>) -> Self {
        let file_deadline = timeout.and_then(|t| now().map(|n| n + t));
        Self {
            inner: Arc::new(Inner {
                read_limit,
                read: AtomicU64::new(0),
                decompressed_limit,
                decompressed: AtomicU64::new(0),
                file_deadline,
                current_deadline: Mutex::new(file_deadline),
                limits_hit: Mutex::new(Vec::new()),
            }),
        }
    }

    /// No limits at all (tests, trusted callers).
    pub fn unlimited() -> Self {
        Self::new(u64::MAX, u64::MAX, None)
    }

    /// Charge `n` bytes read.
    pub fn charge_read(&self, n: u64) -> Result<(), SourceError> {
        self.check_deadline()?;
        let before = self.inner.read.fetch_add(n, Ordering::Relaxed);
        if before.saturating_add(n) > self.inner.read_limit {
            self.hit("read_bytes");
            return Err(SourceError::LimitExceeded("read_bytes"));
        }
        Ok(())
    }

    /// Charge `n` bytes produced by decompression (zip-bomb guard).
    pub fn charge_decompressed(&self, n: u64) -> Result<(), SourceError> {
        self.check_deadline()?;
        let before = self.inner.decompressed.fetch_add(n, Ordering::Relaxed);
        if before.saturating_add(n) > self.inner.decompressed_limit {
            self.hit("decompressed_bytes");
            return Err(SourceError::LimitExceeded("decompressed_bytes"));
        }
        Ok(())
    }

    /// Bytes decompression may still produce.
    pub fn remaining_decompressed(&self) -> u64 {
        self.inner.decompressed_limit.saturating_sub(self.inner.decompressed.load(Ordering::Relaxed))
    }

    /// Fail with [`SourceError::Timeout`] once the deadline has passed.
    pub fn check_deadline(&self) -> Result<(), SourceError> {
        let deadline = *self.inner.current_deadline.lock().unwrap_or_else(PoisonError::into_inner);
        if let (Some(d), Some(n)) = (deadline, now())
            && n >= d
        {
            self.hit("timeout");
            return Err(SourceError::Timeout);
        }
        Ok(())
    }

    /// Bytes read so far.
    pub fn bytes_read(&self) -> u64 {
        self.inner.read.load(Ordering::Relaxed)
    }

    /// Record that a limit stopped work (shown in `diagnostics.limits_hit`).
    pub fn hit(&self, what: &'static str) {
        let mut hits = self.inner.limits_hit.lock().unwrap_or_else(PoisonError::into_inner);
        if !hits.contains(&what) {
            hits.push(what);
        }
    }

    /// Limits hit so far, in first-hit order.
    pub fn limits_hit(&self) -> Vec<&'static str> {
        self.inner.limits_hit.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Start an extractor: its deadline is `timeout` from now, capped by the file deadline.
    pub(crate) fn begin_stage(&self, timeout: Option<Duration>) {
        let stage = timeout.and_then(|t| now().map(|n| n + t));
        let deadline = match (self.inner.file_deadline, stage) {
            (Some(f), Some(s)) => Some(if s < f { s } else { f }),
            (f, s) => f.or(s),
        };
        *self.inner.current_deadline.lock().unwrap_or_else(PoisonError::into_inner) = deadline;
    }

    /// Back to the file deadline only.
    pub(crate) fn end_stage(&self) {
        *self.inner.current_deadline.lock().unwrap_or_else(PoisonError::into_inner) = self.inner.file_deadline;
    }
}
