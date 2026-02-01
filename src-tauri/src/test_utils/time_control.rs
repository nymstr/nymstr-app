//! Time control utilities for testing
//!
//! Provides a mock clock implementation for testing time-dependent behavior
//! such as TTL expiration and message aging.

use chrono::{DateTime, Duration, Utc};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

/// A mock clock that can be controlled for testing
///
/// This allows tests to manipulate time without actually waiting,
/// useful for testing TTL expiration, message aging, etc.
#[derive(Clone)]
pub struct MockClock {
    /// Offset from real time in seconds
    offset_secs: Arc<AtomicI64>,
    /// Whether to use real time (false) or frozen time (true)
    frozen: Arc<std::sync::atomic::AtomicBool>,
    /// Frozen timestamp (only used when frozen is true)
    frozen_time: Arc<std::sync::Mutex<Option<DateTime<Utc>>>>,
}

impl MockClock {
    /// Create a new mock clock starting at the current time
    pub fn new() -> Self {
        Self {
            offset_secs: Arc::new(AtomicI64::new(0)),
            frozen: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            frozen_time: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Create a mock clock frozen at a specific time
    pub fn frozen_at(time: DateTime<Utc>) -> Self {
        let clock = Self::new();
        clock.freeze_at(time);
        clock
    }

    /// Get the current time according to this clock
    pub fn now(&self) -> DateTime<Utc> {
        if self.frozen.load(Ordering::SeqCst) {
            if let Some(frozen) = *self.frozen_time.lock().unwrap() {
                return frozen;
            }
        }

        let offset = self.offset_secs.load(Ordering::SeqCst);
        Utc::now() + Duration::seconds(offset)
    }

    /// Advance the clock by a duration
    pub fn advance(&self, duration: Duration) {
        let secs = duration.num_seconds();
        self.offset_secs.fetch_add(secs, Ordering::SeqCst);

        // Also update frozen time if frozen
        if self.frozen.load(Ordering::SeqCst) {
            if let Ok(mut frozen) = self.frozen_time.lock() {
                if let Some(ref mut time) = *frozen {
                    *time = *time + duration;
                }
            }
        }
    }

    /// Advance the clock by a number of seconds
    pub fn advance_secs(&self, seconds: i64) {
        self.advance(Duration::seconds(seconds));
    }

    /// Advance the clock by a number of minutes
    pub fn advance_mins(&self, minutes: i64) {
        self.advance(Duration::minutes(minutes));
    }

    /// Freeze the clock at the current time
    pub fn freeze(&self) {
        let now = self.now();
        self.freeze_at(now);
    }

    /// Freeze the clock at a specific time
    pub fn freeze_at(&self, time: DateTime<Utc>) {
        *self.frozen_time.lock().unwrap() = Some(time);
        self.frozen.store(true, Ordering::SeqCst);
    }

    /// Unfreeze the clock
    pub fn unfreeze(&self) {
        self.frozen.store(false, Ordering::SeqCst);
        *self.frozen_time.lock().unwrap() = None;
    }

    /// Reset the clock to real time
    pub fn reset(&self) {
        self.offset_secs.store(0, Ordering::SeqCst);
        self.unfreeze();
    }

    /// Check if a timestamp has expired given a TTL in seconds
    pub fn is_expired(&self, timestamp: DateTime<Utc>, ttl_secs: i64) -> bool {
        let now = self.now();
        let age = now.signed_duration_since(timestamp);
        age.num_seconds() > ttl_secs
    }

    /// Get the age of a timestamp in seconds
    pub fn age_secs(&self, timestamp: DateTime<Utc>) -> i64 {
        let now = self.now();
        now.signed_duration_since(timestamp).num_seconds()
    }

    /// Create a timestamp that will be expired given the current time and TTL
    pub fn create_expired_timestamp(&self, ttl_secs: i64) -> DateTime<Utc> {
        self.now() - Duration::seconds(ttl_secs + 1)
    }

    /// Create a timestamp that will not be expired given the current time and TTL
    pub fn create_valid_timestamp(&self, ttl_secs: i64) -> DateTime<Utc> {
        self.now() - Duration::seconds(ttl_secs / 2)
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to run a test with a mock clock
pub async fn with_mock_clock<F, Fut, T>(f: F) -> T
where
    F: FnOnce(MockClock) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let clock = MockClock::new();
    f(clock).await
}

/// Create a timestamp string for database insertion
pub fn timestamp_string(time: DateTime<Utc>) -> String {
    time.to_rfc3339()
}

/// Parse a timestamp string from the database
pub fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_clock_default() {
        let clock = MockClock::new();
        let now = Utc::now();
        let clock_now = clock.now();

        // Should be within 1 second of real time
        let diff = (clock_now - now).num_seconds().abs();
        assert!(diff <= 1);
    }

    #[test]
    fn test_mock_clock_advance() {
        let clock = MockClock::new();
        let before = clock.now();

        clock.advance_secs(60);

        let after = clock.now();
        let diff = (after - before).num_seconds();
        assert!(diff >= 59 && diff <= 61); // Allow 1 second tolerance
    }

    #[test]
    fn test_mock_clock_freeze() {
        let clock = MockClock::new();
        let frozen_time = Utc::now();
        clock.freeze_at(frozen_time);

        std::thread::sleep(std::time::Duration::from_millis(100));

        let clock_now = clock.now();
        assert_eq!(clock_now, frozen_time);
    }

    #[test]
    fn test_mock_clock_is_expired() {
        let clock = MockClock::new();
        let ttl_secs = 300; // 5 minutes

        // Create a timestamp that's 10 minutes old
        let old_timestamp = clock.now() - Duration::minutes(10);
        assert!(clock.is_expired(old_timestamp, ttl_secs));

        // Create a timestamp that's 2 minutes old
        let recent_timestamp = clock.now() - Duration::minutes(2);
        assert!(!clock.is_expired(recent_timestamp, ttl_secs));
    }

    #[test]
    fn test_mock_clock_age() {
        let clock = MockClock::new();
        let timestamp = clock.now() - Duration::seconds(120);

        let age = clock.age_secs(timestamp);
        assert!(age >= 119 && age <= 121);
    }

    #[test]
    fn test_create_expired_timestamp() {
        let clock = MockClock::new();
        let ttl_secs = 300;

        let expired = clock.create_expired_timestamp(ttl_secs);
        assert!(clock.is_expired(expired, ttl_secs));

        let valid = clock.create_valid_timestamp(ttl_secs);
        assert!(!clock.is_expired(valid, ttl_secs));
    }

    #[test]
    fn test_advance_frozen_clock() {
        let clock = MockClock::new();
        let initial = Utc::now();
        clock.freeze_at(initial);

        clock.advance_secs(60);

        let expected = initial + Duration::seconds(60);
        assert_eq!(clock.now(), expected);
    }

    #[test]
    fn test_timestamp_string_roundtrip() {
        let original = Utc::now();
        let s = timestamp_string(original);
        let parsed = parse_timestamp(&s).unwrap();

        // Should be equal to the millisecond (RFC3339 preserves subsec precision)
        let diff = (original - parsed).num_milliseconds().abs();
        assert!(diff < 1000);
    }
}
