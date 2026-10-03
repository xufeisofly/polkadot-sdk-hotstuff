use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::time::{sleep, Duration, Instant, Sleep};

// #[cfg(test)]
// #[path = "tests/timer_tests.rs"]
// pub mod timer_tests;

pub struct Timer {
    sleep: Option<Pin<Box<Sleep>>>, // None = stopped
}

impl Timer {
    pub fn new() -> Self {
        Self { sleep: None }
    }

    pub fn stop(&mut self) {
        self.sleep = None;
    }

    pub fn start(&mut self, duration: u64) {
        self.sleep = Some(Box::pin(sleep(Duration::from_millis(duration))));
    }
}

impl Future for Timer {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(sleep) = self.sleep.as_mut() {
            sleep.as_mut().poll(cx)
        } else {
            Poll::Pending
        }
    }
}

/// A structure that tracks and adjusts view durations
/// using incremental mean and variance (Welford's algorithm).
#[derive(Debug)]
pub struct ViewDuration {
    mul: f64,
    limit: u64,
    count: u64,
    start_time: Option<Instant>,
    mean: f64,
    m2: f64,
    prev_m2: f64,
    min: f64,
    max: f64,
}

impl ViewDuration {
    /// Create a new `ViewDuration`
    ///
    /// - `sample_size`: number of past views to consider
    /// - `start_timeout`: initial view duration (in milliseconds)
    /// - `max_timeout`: maximum allowed view duration (ms, <= 0 means no limit)
    /// - `min_timeout`: minimum allowed view duration (ms)
    /// - `multiplier`: factor applied to the duration when a timeout occurs
    pub fn new(
        sample_size: u64,
        start_timeout: f64,
        max_timeout: f64,
        min_timeout: f64,
        multiplier: f64,
    ) -> Self {
        assert_ne!(sample_size, 0, "sample_size must be greater than 0");
        assert!(min_timeout > 0.0, "min_timeout must be greater than 0");
        let mut initial = start_timeout;
        if max_timeout > 0.0 && initial > max_timeout {
            initial = max_timeout;
        }
        if initial < min_timeout {
            initial = min_timeout;
        }
        Self {
            mul: multiplier,
            limit: sample_size,
            count: 0,
            start_time: None,
            mean: initial,
            m2: 0.0,
            prev_m2: 0.0,
            min: min_timeout,
            max: max_timeout,
        }
    }

    /// Mark the start of a new view
    pub fn view_started(&mut self) {
        self.start_time = Some(Instant::now());
    }

    /// Mark a view as successful and update statistics
    pub fn view_succeeded(&mut self) {
        let Some(start) = self.start_time.take() else {
            return; // If no start time was recorded, ignore
        };

        let duration_ms = (Instant::now() - start).as_millis() as f64;
        self.count += 1;

        // Roll over variance statistics every `limit` samples
        if self.count % self.limit == 0 {
            self.prev_m2 = self.m2;
            self.m2 = 0.0;
        }

        // Incremental mean update
        let c = if self.count > self.limit {
            self.mean -= self.mean / (self.limit as f64);
            self.limit as f64
        } else {
            self.count as f64
        };

        let d1 = duration_ms - self.mean;
        self.mean += d1 / c;
        let d2 = duration_ms - self.mean;
        self.m2 += d1 * d2;
    }

    /// Grow timeout duration after a timeout.
    /// Ensure the next timeout duration is strictly larger than the previous one
    /// (unless we already hit max cap).
    pub fn view_timeout(&mut self) {
        let prev_duration = self.duration();
        self.mean *= self.mul;
        if self.mean < self.min {
            self.mean = self.min;
        }
        if self.max > 0.0 && self.mean > self.max {
            self.mean = self.max;
        }

        let next_duration = self.duration();
        if next_duration <= prev_duration {
            let min_required = prev_duration.saturating_add(1);
            let max_cap = if self.max > 0.0 {
                (self.max as u64).max(self.min as u64)
            } else {
                u64::MAX
            };
            if min_required <= max_cap {
                self.mean = (min_required as f64).max(self.min);
                if self.max > 0.0 && self.mean > self.max {
                    self.mean = self.max;
                }
            }
        }
    }

    fn stat_duration_ms(&self) -> u64 {
        let conf = 1.96f64; // 95% confidence
        let mut dev = 0.0;

        if self.count > 1 {
            let mut c = self.count as f64;
            let mut m2_acc = self.m2;

            if self.count >= self.limit {
                c = (self.limit + (self.count % self.limit)) as f64;
                m2_acc += self.prev_m2;
            }
            dev = (m2_acc / c).sqrt();
        }

        let mut duration_ms = self.mean + dev * conf;
        if duration_ms < self.min {
            duration_ms = self.min;
        }
        if self.max > 0.0 && duration_ms > self.max {
            duration_ms = self.max;
        }

        // Keep a small floor to avoid 0ms timeout loops under extremely fast views.
        // Once it reaches 0ms, it will enter an infinite loop,
        // causing the node to lose its ability to process consensus messages.
        (duration_ms as u64).max(self.min as u64)
    }

    /// Compute the recommended view duration (in milliseconds)
    pub fn duration(&self) -> u64 {
        self.stat_duration_ms()
    }
}
