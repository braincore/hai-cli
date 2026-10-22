//! Throttling for API requests.
//!
//! Initial use case is for throttling requests from asset-app gateways as apps
//! can make many requests without managing their own rate limiting. Also,
//! asset-app handling of 429s tends to be poor so it's best to limit their
//! exposure to it.
//!
//! A single process-wide `ApiLimiter` is shared by every gateway so that many
//! asset-apps (e.g. all waking up at once after the machine resumes) do not
//! stampede the API. While the API can handle it, the API will begin rejecting
//! requests.
//!
//! For simplicity, requests are delay rather than rejected until the request
//! has been queued for too long (at that point, a 429 is returned).
//!
//! Three stategies are used:
//! 1. Token bucket: smooths the request rate.
//! 2. Semaphore: caps simultaneously in-flight requests.
//! 3. Global pause: when the server responds with 429, everyone backs off
//!    briefly (with jitter) rather than retrying in lockstep.

use rand::Rng;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore, SemaphorePermit};

const MAX_IN_FLIGHT: usize = 6;
const REFILL_PER_SEC: f64 = 10.0;
const BURST: f64 = 20.0;
const MAX_QUEUE_WAIT: Duration = Duration::from_secs(30);
const RATE_LIMITED_PAUSE: Duration = Duration::from_secs(2);
const RATE_LIMITED_PAUSE_JITTER_MS: u64 = 1000;

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
pub struct ApiLimiter {
    in_flight: Semaphore,
    /// tokio mutex serves waiters in FIFO order
    bucket: Mutex<Bucket>,
    /// Ensures a pause never blocks behind a waiter for the token bucket.
    paused_until: StdMutex<Option<Instant>>,
}

/// Returned when a request waited in the queue for too long.
#[derive(Debug)]
pub struct QueueTimeout;

/// Holds an in-flight slot. Drop it once the response has been fully read.
pub struct ApiPermit<'a> {
    _permit: SemaphorePermit<'a>,
}

impl ApiLimiter {
    fn new() -> Self {
        ApiLimiter {
            in_flight: Semaphore::new(MAX_IN_FLIGHT),
            bucket: Mutex::new(Bucket {
                tokens: BURST,
                last_refill: Instant::now(),
            }),
            paused_until: StdMutex::new(None),
        }
    }

    /// Waits for a rate token and an in-flight slot (or times out).
    pub async fn acquire(&self) -> Result<ApiPermit<'_>, QueueTimeout> {
        tokio::time::timeout(MAX_QUEUE_WAIT, async {
            self.take_token().await;
            let permit = self
                .in_flight
                .acquire()
                .await
                .expect("limiter semaphore is never closed");
            ApiPermit { _permit: permit }
        })
        .await
        .map_err(|_| {
            tracing::warn!("gateway request exceeded max queue wait");
            QueueTimeout
        })
    }

    /// Call when api responds with 429 to backoff all gateway requests.
    pub fn on_rate_limited(&self) {
        let jitter_ms = rand::rng().random_range(0..RATE_LIMITED_PAUSE_JITTER_MS);
        let until = Instant::now() + RATE_LIMITED_PAUSE + Duration::from_millis(jitter_ms);
        let mut paused_until = self.paused_until.lock().unwrap();
        if paused_until.map_or(true, |cur| cur < until) {
            *paused_until = Some(until);
        }
        tracing::warn!("API rate limited: pausing gateway traffic");
    }

    async fn take_token(&self) {
        let mut bucket = self.bucket.lock().await;
        loop {
            let now = Instant::now();
            let paused_until = *self.paused_until.lock().unwrap();
            if let Some(until) = paused_until
                && now < until
            {
                tokio::time::sleep_until(until.into()).await;
                continue;
            }

            let elapsed = now.saturating_duration_since(bucket.last_refill);
            bucket.tokens = (bucket.tokens + elapsed.as_secs_f64() * REFILL_PER_SEC).min(BURST);
            bucket.last_refill = now;

            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                return;
            }
            let wait = Duration::from_secs_f64((1.0 - bucket.tokens) / REFILL_PER_SEC);
            tokio::time::sleep(wait).await;
        }
    }
}

/// The process-wide (singleton) limiter shared by all gateways.
pub fn gateway_limiter() -> Arc<ApiLimiter> {
    static LIMITER: OnceLock<Arc<ApiLimiter>> = OnceLock::new();
    LIMITER.get_or_init(|| Arc::new(ApiLimiter::new())).clone()
}
