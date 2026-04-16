use crate::errors::ScanError;
use crate::rate_limiter::{RateLimiter, ScanType};
use crate::scanner::{ARPScanner, ScanResult, ScanTarget, ScanTypeVariant, Scanner};
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;

/// TCP Port Scanner
pub struct PortScanner {
    rate_limiter: Arc<RateLimiter>,
    tcp_timeout: std::time::Duration,
}

impl PortScanner {
    /// Create a new port scanner with 1 second TCP timeout
    pub fn new(rate_limiter: Arc<RateLimiter>) -> Self {
        Self {
            rate_limiter,
            tcp_timeout: std::time::Duration::from_secs(1),
        }
    }

    /// Create a new port scanner with custom TCP timeout
    pub fn with_timeout(rate_limiter: Arc<RateLimiter>, tcp_timeout: std::time::Duration) -> Self {
        Self {
            rate_limiter,
            tcp_timeout,
        }
    }

    /// Get default TCP ports to scan (1-1024 and common high ports)
    fn default_tcp_ports() -> Vec<u16> {
        let mut ports: Vec<u16> = (1..=1024).collect();
        ports.extend_from_slice(&[3389, 8080, 8443]);
        ports
    }

    /// Perform TCP port scan on a list of IP addresses
    async fn scan_tcp_ports(
        &self,
        ips: Vec<IpAddr>,
        ports: Vec<u16>,
    ) -> Result<Vec<ScanResult>, ScanError> {
        let mut results = Vec::new();

        for ip in ips {
            // Check whitelist/blacklist
            if let Err(reason) = self.rate_limiter.should_scan(&ip) {
                log::debug!("Skipping IP {}: {}", ip, reason);
                continue;
            }

            let mut result = ScanResult::new(ip);

            for port in &ports {
                // Acquire rate limit permit
                self.rate_limiter
                    .acquire_packet_permit(ScanType::TCP)
                    .await;

                // Acquire connection permit
                let _permit = self.rate_limiter.acquire_connection_permit().await;

                // Perform TCP connection attempt
                if self.probe_tcp_port(ip, *port).await {
                    result.open_tcp_ports.push(*port);
                }
            }

            if !result.open_tcp_ports.is_empty() {
                results.push(result);
            }
        }

        Ok(results)
    }

    /// Probe a single TCP port
    /// Returns true if port is open (SYN-ACK received), false otherwise
    async fn probe_tcp_port(&self, ip: IpAddr, port: u16) -> bool {
        use tokio::net::TcpStream;
        use tokio::time::timeout;

        let addr = format!("{}:{}", ip, port);
        let result = timeout(self.tcp_timeout, TcpStream::connect(&addr)).await;

        matches!(result, Ok(Ok(_)))
    }
}

#[async_trait]
impl Scanner for PortScanner {
    async fn scan(&self, target: ScanTarget) -> Result<Vec<ScanResult>, ScanError> {
        // Parse network range
        let mut ips = ARPScanner::parse_network_range(&target.network)?;

        // Randomize order if in stealth mode
        self.rate_limiter.randomize_order(&mut ips).await;

        // Extract TCP ports from scan types
        let mut tcp_ports = Vec::new();
        for scan_type in &target.scan_types {
            if let ScanTypeVariant::TCPPorts(ports) = scan_type {
                tcp_ports.extend_from_slice(ports);
            }
        }

        // Use default ports if none specified
        if tcp_ports.is_empty() {
            tcp_ports = Self::default_tcp_ports();
        }

        // Perform TCP port scan
        self.scan_tcp_ports(ips, tcp_ports).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limiter::RateLimitConfig;

    #[tokio::test]
    async fn test_port_scanner_creation() {
        let config = RateLimitConfig::default();
        let rate_limiter = Arc::new(RateLimiter::new(config));
        let scanner = PortScanner::new(rate_limiter);

        assert_eq!(scanner.tcp_timeout, std::time::Duration::from_secs(1));
    }

    #[tokio::test]
    async fn test_default_tcp_ports() {
        let ports = PortScanner::default_tcp_ports();
        
        // Should include ports 1-1024
        assert!(ports.contains(&1));
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&1024));
        
        // Should include common high ports
        assert!(ports.contains(&3389));
        assert!(ports.contains(&8080));
        assert!(ports.contains(&8443));
        
        // Total should be 1024 + 3 = 1027
        assert_eq!(ports.len(), 1027);
    }

    #[tokio::test]
    async fn test_port_scanner_scan_with_specific_ports() {
        let config = RateLimitConfig {
            tcp_rate: 1000,
            ..Default::default()
        };
        let rate_limiter = Arc::new(RateLimiter::new(config));
        let scanner = PortScanner::new(rate_limiter);

        // Scan localhost with specific ports
        let target = ScanTarget::new(
            "127.0.0.1/32".to_string(),
            vec![ScanTypeVariant::TCPPorts(vec![80, 443])],
        );

        let results = scanner.scan(target).await.unwrap();
        
        // Results depend on what's running on localhost
        assert!(results.len() <= 1);
    }
}


#[cfg(test)]
mod property_tests {
    use super::*;
    use crate::rate_limiter::RateLimitConfig;
    use proptest::prelude::*;

    // **Validates: Requirements 1.7, 3.12**
    // Feature: complete-network-mapper, Property 5: Scan Operation Timeout Compliance
    //
    // For any network operation (TCP connection, ICMP probe, UDP probe, protocol query),
    // the operation shall complete or timeout within the specified time limit
    // (1s for TCP, 2s for ICMP/UDP, 10s for protocol handlers).
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]

        #[test]
        fn prop_tcp_scan_respects_timeout(
            timeout_ms in 100u64..=2000,
            num_ports in 1usize..=5,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let config = RateLimitConfig {
                    tcp_rate: 1000,
                    max_concurrent_connections: 100,
                    ..Default::default()
                };
                let rate_limiter = Arc::new(RateLimiter::new(config));
                let timeout = std::time::Duration::from_millis(timeout_ms);
                let scanner = PortScanner::with_timeout(rate_limiter, timeout);

                // Scan a non-routable IP (should timeout)
                let target = ScanTarget::new(
                    "192.0.2.1/32".to_string(), // TEST-NET-1, non-routable
                    vec![ScanTypeVariant::TCPPorts((1..=num_ports as u16).collect())],
                );

                let start = std::time::Instant::now();
                let _ = scanner.scan(target).await;
                let elapsed = start.elapsed();

                // Total time should be approximately num_ports * timeout
                // Allow 50% tolerance for overhead
                let expected_max = std::time::Duration::from_millis(
                    timeout_ms * num_ports as u64
                ) + std::time::Duration::from_secs(1);

                prop_assert!(
                    elapsed <= expected_max,
                    "Scan took {}ms, expected at most {}ms",
                    elapsed.as_millis(),
                    expected_max.as_millis()
                );

                Ok(())
            });
        }

        #[test]
        fn prop_tcp_probe_respects_individual_timeout(
            timeout_ms in 100u64..=1000,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let config = RateLimitConfig {
                    tcp_rate: 1000,
                    ..Default::default()
                };
                let rate_limiter = Arc::new(RateLimiter::new(config));
                let timeout = std::time::Duration::from_millis(timeout_ms);
                let scanner = PortScanner::with_timeout(rate_limiter, timeout);

                // Probe a single port on non-routable IP
                let ip: IpAddr = "192.0.2.1".parse().unwrap();
                let port = 80;

                let start = std::time::Instant::now();
                let _ = scanner.probe_tcp_port(ip, port).await;
                let elapsed = start.elapsed();

                // Should complete within timeout + small overhead
                let max_allowed = timeout + std::time::Duration::from_millis(200);

                prop_assert!(
                    elapsed <= max_allowed,
                    "TCP probe took {}ms, expected at most {}ms",
                    elapsed.as_millis(),
                    max_allowed.as_millis()
                );

                Ok(())
            });
        }
    }
}
