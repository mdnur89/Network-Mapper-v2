use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};

/// Scan type for rate limiting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanType {
    ARP,
    ICMP,
    TCP,
    UDP,
}

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub max_packets_per_second: u32,
    pub max_concurrent_connections: u32,
    pub arp_rate: u32,
    pub icmp_rate: u32,
    pub tcp_rate: u32,
    pub udp_rate: u32,
    pub stealth_mode: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_packets_per_second: 100,
            max_concurrent_connections: 50,
            arp_rate: 100,
            icmp_rate: 100,
            tcp_rate: 100,
            udp_rate: 100,
            stealth_mode: false,
        }
    }
}

/// Token bucket implementation for rate limiting
struct TokenBucket {
    capacity: u32,
    tokens: Arc<Mutex<f64>>,
    refill_rate: f64, // tokens per second
    last_refill: Arc<Mutex<Instant>>,
}

impl TokenBucket {
    fn new(packets_per_second: u32) -> Self {
        let capacity = packets_per_second.max(1);
        Self {
            capacity,
            tokens: Arc::new(Mutex::new(capacity as f64)),
            refill_rate: packets_per_second as f64,
            last_refill: Arc::new(Mutex::new(Instant::now())),
        }
    }

    async fn acquire(&self) {
        loop {
            // Refill tokens based on elapsed time
            let now = Instant::now();
            let mut last_refill = self.last_refill.lock().await;
            let elapsed = now.duration_since(*last_refill).as_secs_f64();

            let mut tokens = self.tokens.lock().await;

            // Add tokens based on elapsed time
            let new_tokens = elapsed * self.refill_rate;
            *tokens = (*tokens + new_tokens).min(self.capacity as f64);
            *last_refill = now;

            // Try to consume a token
            if *tokens >= 1.0 {
                *tokens -= 1.0;
                break;
            }

            // Not enough tokens, calculate wait time
            drop(tokens);
            drop(last_refill);

            let wait_time = Duration::from_secs_f64(1.0 / self.refill_rate);
            tokio::time::sleep(wait_time).await;
        }
    }
}

/// Rate limiter for controlling scanning intensity
pub struct RateLimiter {
    config: RateLimitConfig,
    arp_limiter: TokenBucket,
    icmp_limiter: TokenBucket,
    tcp_limiter: TokenBucket,
    udp_limiter: TokenBucket,
    connection_limiter: Arc<Semaphore>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            arp_limiter: TokenBucket::new(config.arp_rate),
            icmp_limiter: TokenBucket::new(config.icmp_rate),
            tcp_limiter: TokenBucket::new(config.tcp_rate),
            udp_limiter: TokenBucket::new(config.udp_rate),
            connection_limiter: Arc::new(Semaphore::new(
                config.max_concurrent_connections as usize,
            )),
            config,
        }
    }

    /// Acquire a permit to send a packet of the specified scan type
    /// This method will wait asynchronously until a permit is available
    pub async fn acquire_packet_permit(&self, scan_type: ScanType) {
        let limiter = match scan_type {
            ScanType::ARP => &self.arp_limiter,
            ScanType::ICMP => &self.icmp_limiter,
            ScanType::TCP => &self.tcp_limiter,
            ScanType::UDP => &self.udp_limiter,
        };

        limiter.acquire().await;
    }

    /// Acquire a permit to make a connection
    /// Returns a ConnectionPermit guard that releases the permit when dropped
    pub async fn acquire_connection_permit(&self) -> ConnectionPermit {
        let permit = self
            .connection_limiter
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        ConnectionPermit { _permit: permit }
    }

    /// Get the current configuration
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }
}

/// Guard for connection permits
/// The permit is automatically released when this guard is dropped
pub struct ConnectionPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    #[tokio::test]
    async fn test_token_bucket_basic() {
        let bucket = TokenBucket::new(10);

        // Should be able to acquire immediately
        bucket.acquire().await;
    }

    #[tokio::test]
    async fn test_rate_limiter_creation() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::new(config);

        assert_eq!(limiter.config().max_packets_per_second, 100);
        assert_eq!(limiter.config().max_concurrent_connections, 50);
    }

    #[tokio::test]
    async fn test_acquire_packet_permit() {
        let config = RateLimitConfig {
            arp_rate: 10,
            icmp_rate: 10,
            tcp_rate: 10,
            udp_rate: 10,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // Should be able to acquire permits for all scan types
        limiter.acquire_packet_permit(ScanType::ARP).await;
        limiter.acquire_packet_permit(ScanType::ICMP).await;
        limiter.acquire_packet_permit(ScanType::TCP).await;
        limiter.acquire_packet_permit(ScanType::UDP).await;
    }

    #[tokio::test]
    async fn test_acquire_connection_permit() {
        let config = RateLimitConfig {
            max_concurrent_connections: 5,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // Acquire a connection permit
        let _permit = limiter.acquire_connection_permit().await;
        // Permit should be held until dropped
    }

    #[tokio::test]
    async fn test_per_scan_type_limits() {
        let config = RateLimitConfig {
            arp_rate: 50,
            icmp_rate: 100,
            tcp_rate: 75,
            udp_rate: 25,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // Each scan type should have its own rate limit
        limiter.acquire_packet_permit(ScanType::ARP).await;
        limiter.acquire_packet_permit(ScanType::ICMP).await;
        limiter.acquire_packet_permit(ScanType::TCP).await;
        limiter.acquire_packet_permit(ScanType::UDP).await;
    }

    // Property-based tests
    #[cfg(test)]
    mod property_tests {
        use super::*;
        use proptest::prelude::*;

        // **Validates: Requirements 1.11, 10.1, 10.2, 10.3, 10.4**
        // Feature: complete-network-mapper, Property 4: Rate Limiting Enforcement
        //
        // For any scanning operation, the measured packet rate shall not exceed the configured
        // maximum packets per second, and concurrent connections shall not exceed the configured maximum.
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_packet_rate_does_not_exceed_limit(
                packets_per_second in 1u32..=200,
                num_packets in 10u32..=50,
            ) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let config = RateLimitConfig {
                        arp_rate: packets_per_second,
                        icmp_rate: packets_per_second,
                        tcp_rate: packets_per_second,
                        udp_rate: packets_per_second,
                        max_packets_per_second: packets_per_second,
                        ..Default::default()
                    };
                    let limiter = Arc::new(RateLimiter::new(config));

                    // Test each scan type
                    for scan_type in [ScanType::ARP, ScanType::ICMP, ScanType::TCP, ScanType::UDP] {
                        let start = Instant::now();

                        // Acquire permits for the specified number of packets
                        for _ in 0..num_packets {
                            limiter.acquire_packet_permit(scan_type).await;
                        }

                        let elapsed = start.elapsed();
                        let elapsed_secs = elapsed.as_secs_f64();

                        // Calculate the actual rate
                        let actual_rate = num_packets as f64 / elapsed_secs;

                        // The actual rate should not exceed the configured rate
                        // Allow 10% tolerance for timing variations
                        let tolerance = packets_per_second as f64 * 1.1;
                        prop_assert!(
                            actual_rate <= tolerance,
                            "Packet rate {} exceeded limit {} (with 10% tolerance) for {:?}",
                            actual_rate,
                            packets_per_second,
                            scan_type
                        );

                        // If we sent more packets than the rate allows per second,
                        // it should have taken at least that long
                        if num_packets > packets_per_second {
                            let min_expected_time = (num_packets as f64 / packets_per_second as f64) * 0.9;
                            prop_assert!(
                                elapsed_secs >= min_expected_time,
                                "Operation completed too quickly: {}s, expected at least {}s",
                                elapsed_secs,
                                min_expected_time
                            );
                        }
                    }
                });
            }

            #[test]
            fn prop_concurrent_connections_do_not_exceed_limit(
                max_connections in 1u32..=20,
                num_attempts in 5u32..=30,
            ) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let config = RateLimitConfig {
                        max_concurrent_connections: max_connections,
                        ..Default::default()
                    };
                    let limiter = Arc::new(RateLimiter::new(config));

                    // Track active connections
                    let active_count = Arc::new(tokio::sync::Mutex::new(0u32));
                    let max_observed = Arc::new(tokio::sync::Mutex::new(0u32));

                    // Spawn tasks that acquire connection permits
                    let mut handles = vec![];
                    for _ in 0..num_attempts {
                        let limiter = Arc::clone(&limiter);
                        let active_count = Arc::clone(&active_count);
                        let max_observed = Arc::clone(&max_observed);

                        let handle = tokio::spawn(async move {
                            let _permit = limiter.acquire_connection_permit().await;

                            // Increment active count
                            let mut count = active_count.lock().await;
                            *count += 1;
                            let current = *count;
                            drop(count);

                            // Update max observed
                            let mut max = max_observed.lock().await;
                            if current > *max {
                                *max = current;
                            }
                            drop(max);

                            // Hold the connection for a short time
                            tokio::time::sleep(Duration::from_millis(10)).await;

                            // Decrement active count
                            let mut count = active_count.lock().await;
                            *count -= 1;
                        });

                        handles.push(handle);
                    }

                    // Wait for all tasks to complete
                    for handle in handles {
                        handle.await.unwrap();
                    }

                    // Check that we never exceeded the limit
                    let max = *max_observed.lock().await;
                    prop_assert!(
                        max <= max_connections,
                        "Concurrent connections {} exceeded limit {}",
                        max,
                        max_connections
                    );
                });
            }

            #[test]
            fn prop_per_scan_type_rate_limits_are_independent(
                arp_rate in 10u32..=100,
                icmp_rate in 10u32..=100,
                tcp_rate in 10u32..=100,
                udp_rate in 10u32..=100,
                num_packets in 10u32..=30,
            ) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let config = RateLimitConfig {
                        arp_rate,
                        icmp_rate,
                        tcp_rate,
                        udp_rate,
                        max_packets_per_second: arp_rate.max(icmp_rate).max(tcp_rate).max(udp_rate),
                        ..Default::default()
                    };
                    let limiter = Arc::new(RateLimiter::new(config));

                    // Test that different scan types can run concurrently
                    // without interfering with each other's rate limits
                    let mut handles = vec![];

                    for (scan_type, rate) in [
                        (ScanType::ARP, arp_rate),
                        (ScanType::ICMP, icmp_rate),
                        (ScanType::TCP, tcp_rate),
                        (ScanType::UDP, udp_rate),
                    ] {
                        let limiter = Arc::clone(&limiter);
                        let handle = tokio::spawn(async move {
                            let start = Instant::now();

                            for _ in 0..num_packets {
                                limiter.acquire_packet_permit(scan_type).await;
                            }

                            let elapsed = start.elapsed().as_secs_f64();
                            let actual_rate = num_packets as f64 / elapsed;

                            (scan_type, actual_rate, rate)
                        });
                        handles.push(handle);
                    }

                    // Verify each scan type respected its own limit
                    for handle in handles {
                        let (scan_type, actual_rate, configured_rate) = handle.await.unwrap();
                        let tolerance = configured_rate as f64 * 1.15; // 15% tolerance for concurrent execution
                        prop_assert!(
                            actual_rate <= tolerance,
                            "Scan type {:?} rate {} exceeded limit {} (with tolerance)",
                            scan_type,
                            actual_rate,
                            configured_rate
                        );
                    }
                });
            }
        }
    }
}
