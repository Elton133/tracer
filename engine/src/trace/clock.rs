use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// One monotonic origin per trace.
///
/// `Instant` is backed by `mach_absolute_time` on macOS and
/// `CLOCK_MONOTONIC` on Linux. It never jumps when NTP adjusts the wall
/// clock, which is why durations come from here and not from `SystemTime`.
///
/// These are *userland* timestamps: they record when our code ran, slightly
/// after the kernel saw the packet. V3 packet capture will show that gap.
pub struct Clock {
    origin: Instant,
    pub started_at_unix_ms: f64,
}

impl Clock {
    pub fn start() -> Self {
        let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        Self { origin: Instant::now(), started_at_unix_ms: wall.as_secs_f64() * 1000.0 }
    }

    /// Milliseconds since trace start.
    pub fn now(&self) -> f64 {
        self.origin.elapsed().as_secs_f64() * 1000.0
    }
}
