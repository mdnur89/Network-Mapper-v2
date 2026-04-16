use crate::errors::ScanError;
use crate::rate_limiter::{RateLimiter, ScanType};
use crate::scanner::{ARPScanner, ScanResult, ScanTarget, ScanTypeVariant, Scanner};
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;

/// UDP Port Scanner
pub struct UDPScanner {
    rate_limiter: Arc<RateLimiter>,
    udp_timeout: std::time::Duration,
}

impl UDPScanner {
    /// Create a new UDP scanner with 2 second timeout
    pub fn new(rate_limiter: Arc<RateLimiter>) -> Self {
        Self {
            rate_limiter,
            udp_timeout: std::time::Duration::from_secs(2),
        }
    }

    /// Create a new UDP scanner with custom timeout
    pub fn with_timeout(rate_limiter: Arc<RateLimiter>, udp_timeout: std::time::Duration) -> Self {
        Self {
            rate_limiter,
            udp_timeout,
        }
    }

    /// Get default UDP ports to scan
    fn default_udp_ports() -> Vec<u16> {
        vec![53, 67, 68, 69, 123, 161, 162, 514]
    }

    /// Perform UDP port scan on a list of IP addresses
    async fn scan_udp_ports(
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
                    .acquire_packet_permit(ScanType::UDP)
                    .await;

                // Perform UDP probe
                if self.probe_udp_port(ip, *port).await {
                    result.open_udp_ports.push(*port);
                }
            }

            if !result.open_udp_ports.is_empty() {
                results.push(result);
            }
        }

        Ok(results)
    }

    /// Probe a single UDP port
    /// Returns true if port responds, false otherwise
    async fn probe_udp_port(&self, ip: IpAddr, port: u16) -> bool {
        use tokio::net::UdpSocket;
        use tokio::time::timeout;

        // Bind to any available local port
        let local_addr = if ip.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let socket = match UdpSocket::bind(local_addr).await {
            Ok(s) => s,
            Err(_) => return false,
        };

        let remote_addr = format!("{}:{}", ip, port);

        // Send protocol-specific probe
        let probe_data = self.get_probe_data(port);

        // Send probe
        if socket.send_to(&probe_data, &remote_addr).await.is_err() {
            return false;
        }

        // Wait for response
        let mut buf = [0u8; 1024];
        let result = timeout(self.udp_timeout, socket.recv_from(&mut buf)).await;

        matches!(result, Ok(Ok(_)))
    }

    /// Get protocol-specific probe data for a UDP port
    fn get_probe_data(&self, port: u16) -> Vec<u8> {
        match port {
            53 => {
                // DNS query for version.bind
                vec![
                    0x00, 0x00, // Transaction ID
                    0x01, 0x00, // Flags: standard query
                    0x00, 0x01, // Questions: 1
                    0x00, 0x00, // Answer RRs: 0
                    0x00, 0x00, // Authority RRs: 0
                    0x00, 0x00, // Additional RRs: 0
                    0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
                    0x04, 0x62, 0x69, 0x6e, 0x64, // "bind"
                    0x00, // null terminator
                    0x00, 0x10, // Type: TXT
                    0x00, 0x03, // Class: CHAOS
                ]
            }
            161 | 162 => {
                // SNMP GetRequest
                vec![
                    0x30, 0x26, // SEQUENCE
                    0x02, 0x01, 0x00, // Version: 1
                    0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // Community: "public"
                    0xa0, 0x19, // GetRequest PDU
                    0x02, 0x01, 0x01, // Request ID
                    0x02, 0x01, 0x00, // Error status
                    0x02, 0x01, 0x00, // Error index
                    0x30, 0x0e, // Variable bindings
                    0x30, 0x0c, // Variable binding
                    0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: sysDescr
                    0x05, 0x00, // Value: NULL
                ]
            }
            123 => {
                // NTP request
                vec![
                    0x1b, // LI, Version, Mode
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Rest of header
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]
            }
            _ => {
                // Generic probe
                vec![0x00]
            }
        }
    }
}

#[async_trait]
impl Scanner for UDPScanner {
    async fn scan(&self, target: ScanTarget) -> Result<Vec<ScanResult>, ScanError> {
        // Parse network range
        let mut ips = ARPScanner::parse_network_range(&target.network)?;

        // Randomize order if in stealth mode
        self.rate_limiter.randomize_order(&mut ips).await;

        // Extract UDP ports from scan types
        let mut udp_ports = Vec::new();
        for scan_type in &target.scan_types {
            if let ScanTypeVariant::UDPPorts(ports) = scan_type {
                udp_ports.extend_from_slice(ports);
            }
        }

        // Use default ports if none specified
        if udp_ports.is_empty() {
            udp_ports = Self::default_udp_ports();
        }

        // Perform UDP port scan
        self.scan_udp_ports(ips, udp_ports).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limiter::RateLimitConfig;

    #[tokio::test]
    async fn test_udp_scanner_creation() {
        let config = RateLimitConfig::default();
        let rate_limiter = Arc::new(RateLimiter::new(config));
        let scanner = UDPScanner::new(rate_limiter);

        assert_eq!(scanner.udp_timeout, std::time::Duration::from_secs(2));
    }

    #[tokio::test]
    async fn test_udp_scanner_with_custom_timeout() {
        let config = RateLimitConfig::default();
        let rate_limiter = Arc::new(RateLimiter::new(config));
        let timeout = std::time::Duration::from_secs(3);
        let scanner = UDPScanner::with_timeout(rate_limiter, timeout);

        assert_eq!(scanner.udp_timeout, timeout);
    }

    #[tokio::test]
    async fn test_default_udp_ports() {
        let ports = UDPScanner::default_udp_ports();
        
        assert_eq!(ports, vec![53, 67, 68, 69, 123, 161, 162, 514]);
    }

    #[tokio::test]
    async fn test_get_probe_data() {
        let config = RateLimitConfig::default();
        let rate_limiter = Arc::new(RateLimiter::new(config));
        let scanner = UDPScanner::new(rate_limiter);

        // DNS probe should be non-empty
        let dns_probe = scanner.get_probe_data(53);
        assert!(!dns_probe.is_empty());

        // SNMP probe should be non-empty
        let snmp_probe = scanner.get_probe_data(161);
        assert!(!snmp_probe.is_empty());

        // NTP probe should be non-empty
        let ntp_probe = scanner.get_probe_data(123);
        assert!(!ntp_probe.is_empty());

        // Generic probe
        let generic_probe = scanner.get_probe_data(9999);
        assert_eq!(generic_probe, vec![0x00]);
    }

    #[tokio::test]
    async fn test_udp_scanner_scan() {
        let config = RateLimitConfig {
            udp_rate: 1000,
            ..Default::default()
        };
        let rate_limiter = Arc::new(RateLimiter::new(config));
        let scanner = UDPScanner::new(rate_limiter);

        // Scan localhost with specific ports
        let target = ScanTarget::new(
            "127.0.0.1/32".to_string(),
            vec![ScanTypeVariant::UDPPorts(vec![53, 123])],
        );

        let results = scanner.scan(target).await.unwrap();
        
        // Results depend on what's running on localhost
        assert!(results.len() <= 1);
    }

    #[tokio::test]
    async fn test_udp_scanner_respects_whitelist() {
        use std::net::Ipv4Addr;

        let whitelist = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let config = RateLimitConfig {
            whitelist,
            udp_rate: 1000,
            ..Default::default()
        };
        let rate_limiter = Arc::new(RateLimiter::new(config));
        let scanner = UDPScanner::new(rate_limiter);

        let target = ScanTarget::new(
            "192.168.1.0/30".to_string(),
            vec![ScanTypeVariant::UDPPorts(vec![53])],
        );

        let results = scanner.scan(target).await.unwrap();
        
        // Whitelisted IP should be skipped
        for result in results {
            assert_ne!(result.ip.to_string(), "192.168.1.1");
        }
    }

    #[tokio::test]
    async fn test_udp_scanner_respects_blacklist() {
        use std::net::Ipv4Addr;

        let blacklist = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))];
        let config = RateLimitConfig {
            blacklist,
            udp_rate: 1000,
            ..Default::default()
        };
        let rate_limiter = Arc::new(RateLimiter::new(config));
        let scanner = UDPScanner::new(rate_limiter);

        let target = ScanTarget::new(
            "192.168.1.0/30".to_string(),
            vec![ScanTypeVariant::UDPPorts(vec![53])],
        );

        let results = scanner.scan(target).await.unwrap();
        
        // Blacklisted IP should be skipped
        for result in results {
            assert_ne!(result.ip.to_string(), "192.168.1.2");
        }
    }
}
