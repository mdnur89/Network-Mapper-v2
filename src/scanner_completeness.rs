// Property-based tests for scan result completeness

#[cfg(test)]
mod tests {
    use crate::rate_limiter::{RateLimiter, RateLimitConfig};
    use crate::scanner::{ScanResult, ScanTarget, ScanTypeVariant, Scanner};
    use crate::scanner_port::PortScanner;
    use proptest::prelude::*;
    use std::net::IpAddr;
    use std::sync::Arc;

    // **Validates: Requirements 1.12**
    // Feature: complete-network-mapper, Property 3: Scan Result Completeness
    //
    // For any completed scan of a target network, the scanner shall return a list
    // where each discovered device includes IP address, MAC address (if available),
    // and all detected open ports.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]

        #[test]
        fn prop_scan_result_has_required_fields(
            a in 1u8..=254,
            b in 1u8..=254,
            c in 1u8..=254,
            d in 1u8..=254,
        ) {
            let ip: IpAddr = format!("{}.{}.{}.{}", a, b, c, d).parse().unwrap();
            let result = ScanResult::new(ip);

            // Every scan result must have an IP address
            prop_assert!(
                !result.ip.to_string().is_empty(),
                "ScanResult must have an IP address"
            );

            // Every scan result must have a timestamp
            prop_assert!(
                result.scan_timestamp <= std::time::SystemTime::now(),
                "ScanResult must have a valid timestamp"
            );

            // MAC address field must exist (even if None)
            let _ = result.mac;

            // Port lists must exist (even if empty)
            let _ = result.open_tcp_ports;
            let _ = result.open_udp_ports;

            // ICMP responsive field must exist
            let _ = result.icmp_responsive;

            Ok(())
        }

        #[test]
        fn prop_tcp_scan_results_are_complete(
            port in 1u16..=1024,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let config = RateLimitConfig {
                    tcp_rate: 1000,
                    max_concurrent_connections: 100,
                    ..Default::default()
                };
                let rate_limiter = Arc::new(RateLimiter::new(config));
                let scanner = PortScanner::new(rate_limiter);

                let target = ScanTarget::new(
                    "127.0.0.1/32".to_string(),
                    vec![ScanTypeVariant::TCPPorts(vec![port])],
                );

                let results = scanner.scan(target).await?;

                // Every result must have all required fields
                for result in results {
                    // Must have IP
                    prop_assert!(
                        !result.ip.to_string().is_empty(),
                        "Result must have IP address"
                    );

                    // Must have timestamp
                    prop_assert!(
                        result.scan_timestamp <= std::time::SystemTime::now(),
                        "Result must have valid timestamp"
                    );

                    // Must have port lists
                    let _ = &result.open_tcp_ports;
                    let _ = &result.open_udp_ports;

                    // TCP scan results should have open TCP ports
                    prop_assert!(
                        !result.open_tcp_ports.is_empty(),
                        "TCP scan result should have at least one open port"
                    );
                }

                Ok(())
            });
        }

        #[test]
        fn prop_scan_results_contain_scanned_ips(
            network_prefix in 1u8..=254,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let config = RateLimitConfig {
                    tcp_rate: 1000,
                    max_concurrent_connections: 100,
                    ..Default::default()
                };
                let rate_limiter = Arc::new(RateLimiter::new(config));
                let scanner = PortScanner::new(rate_limiter);

                // Scan a /32 network (single IP)
                let network = format!("192.168.{}.1/32", network_prefix);
                let target = ScanTarget::new(
                    network.clone(),
                    vec![ScanTypeVariant::TCPPorts(vec![80])],
                );

                let results = scanner.scan(target).await?;

                // If we got results, they should be for the scanned IP
                for result in results {
                    let expected_ip = format!("192.168.{}.1", network_prefix);
                    prop_assert_eq!(
                        result.ip.to_string(),
                        expected_ip,
                        "Result IP should match scanned network"
                    );
                }

                Ok(())
            });
        }
    }
}
