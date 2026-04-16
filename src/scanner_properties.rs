// Property-based tests for scanner functionality

#[cfg(test)]
mod tests {
    use crate::models::MacAddr;
    use crate::rate_limiter::{RateLimiter, RateLimitConfig};
    use crate::scanner::{ScanResult, ScanTarget, ScanTypeVariant, Scanner};
    use crate::scanner_port::PortScanner;
    use crate::scanner_udp::UDPScanner;
    use proptest::prelude::*;
    use std::net::IpAddr;
    use std::sync::Arc;

    // **Validates: Requirements 1.2, 1.4, 1.5, 1.8, 1.10**
    // Feature: complete-network-mapper, Property 2: Scan Response Recording
    //
    // For any scan response received (ARP reply, ICMP reply, TCP SYN-ACK, UDP response),
    // the scanner shall record the response with the correct device identification
    // (IP, MAC, port) and status.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]

        #[test]
        fn prop_scan_result_records_ip_correctly(
            a in 1u8..=254,
            b in 1u8..=254,
            c in 1u8..=254,
            d in 1u8..=254,
        ) {
            let ip: IpAddr = format!("{}.{}.{}.{}", a, b, c, d).parse().unwrap();
            let result = ScanResult::new(ip);

            prop_assert_eq!(result.ip, ip, "ScanResult should record IP correctly");
            Ok(())
        }

        #[test]
        fn prop_scan_result_records_mac_correctly(
            mac_bytes in prop::array::uniform6(0u8..=255),
        ) {
            let ip: IpAddr = "192.168.1.1".parse().unwrap();
            let mut result = ScanResult::new(ip);
            let mac = MacAddr::new(mac_bytes);

            result.mac = Some(mac);

            prop_assert_eq!(
                result.mac,
                Some(mac),
                "ScanResult should record MAC address correctly"
            );
            Ok(())
        }

        #[test]
        fn prop_scan_result_records_tcp_ports_correctly(
            ports in prop::collection::vec(1u16..=65535, 1..=10),
        ) {
            let ip: IpAddr = "192.168.1.1".parse().unwrap();
            let mut result = ScanResult::new(ip);

            for port in &ports {
                result.open_tcp_ports.push(*port);
            }

            prop_assert_eq!(
                result.open_tcp_ports.len(),
                ports.len(),
                "ScanResult should record all TCP ports"
            );

            for (i, port) in ports.iter().enumerate() {
                prop_assert_eq!(
                    result.open_tcp_ports[i],
                    *port,
                    "TCP port {} should be recorded correctly",
                    port
                );
            }
            Ok(())
        }

        #[test]
        fn prop_scan_result_records_udp_ports_correctly(
            ports in prop::collection::vec(1u16..=65535, 1..=10),
        ) {
            let ip: IpAddr = "192.168.1.1".parse().unwrap();
            let mut result = ScanResult::new(ip);

            for port in &ports {
                result.open_udp_ports.push(*port);
            }

            prop_assert_eq!(
                result.open_udp_ports.len(),
                ports.len(),
                "ScanResult should record all UDP ports"
            );

            for (i, port) in ports.iter().enumerate() {
                prop_assert_eq!(
                    result.open_udp_ports[i],
                    *port,
                    "UDP port {} should be recorded correctly",
                    port
                );
            }
            Ok(())
        }

        #[test]
        fn prop_scan_result_records_icmp_response_correctly(
            responsive in prop::bool::ANY,
        ) {
            let ip: IpAddr = "192.168.1.1".parse().unwrap();
            let mut result = ScanResult::new(ip);

            result.icmp_responsive = responsive;

            prop_assert_eq!(
                result.icmp_responsive,
                responsive,
                "ScanResult should record ICMP responsiveness correctly"
            );
            Ok(())
        }

        #[test]
        fn prop_scan_result_is_active_with_any_response(
            has_mac in prop::bool::ANY,
            has_icmp in prop::bool::ANY,
            num_tcp_ports in 0usize..=5,
            num_udp_ports in 0usize..=5,
        ) {
            let ip: IpAddr = "192.168.1.1".parse().unwrap();
            let mut result = ScanResult::new(ip);

            if has_mac {
                result.mac = Some(MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
            }

            if has_icmp {
                result.icmp_responsive = true;
            }

            for i in 0..num_tcp_ports {
                result.open_tcp_ports.push(80 + i as u16);
            }

            for i in 0..num_udp_ports {
                result.open_udp_ports.push(53 + i as u16);
            }

            let expected_active = has_mac || has_icmp || num_tcp_ports > 0 || num_udp_ports > 0;

            prop_assert_eq!(
                result.is_active(),
                expected_active,
                "ScanResult.is_active() should return true if any response was recorded"
            );
            Ok(())
        }

        #[test]
        fn prop_scan_result_timestamp_is_recent(
            _dummy in 0u8..=1, // Just to make it a property test
        ) {
            let ip: IpAddr = "192.168.1.1".parse().unwrap();
            let before = std::time::SystemTime::now();
            let result = ScanResult::new(ip);
            let after = std::time::SystemTime::now();

            // Timestamp should be between before and after
            prop_assert!(
                result.scan_timestamp >= before && result.scan_timestamp <= after,
                "ScanResult timestamp should be set to current time"
            );
            Ok(())
        }

        #[test]
        fn prop_tcp_scanner_records_open_ports(
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

                // Scan localhost with a specific port
                let target = ScanTarget::new(
                    "127.0.0.1/32".to_string(),
                    vec![ScanTypeVariant::TCPPorts(vec![port])],
                );

                let results = scanner.scan(target).await?;

                // If we got results, verify they contain the scanned IP
                for result in results {
                    prop_assert_eq!(
                        result.ip.to_string(),
                        "127.0.0.1",
                        "Result should contain the scanned IP"
                    );

                    // If port is open, it should be in the list
                    if !result.open_tcp_ports.is_empty() {
                        prop_assert!(
                            result.open_tcp_ports.contains(&port),
                            "Open port {} should be recorded in results",
                            port
                        );
                    }
                }

                Ok(())
            });
        }

        #[test]
        fn prop_udp_scanner_records_open_ports(
            port in prop::sample::select(vec![53u16, 123, 161]),
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let config = RateLimitConfig {
                    udp_rate: 1000,
                    ..Default::default()
                };
                let rate_limiter = Arc::new(RateLimiter::new(config));
                let scanner = UDPScanner::new(rate_limiter);

                // Scan localhost with a specific port
                let target = ScanTarget::new(
                    "127.0.0.1/32".to_string(),
                    vec![ScanTypeVariant::UDPPorts(vec![port])],
                );

                let results = scanner.scan(target).await?;

                // If we got results, verify they contain the scanned IP
                for result in results {
                    prop_assert_eq!(
                        result.ip.to_string(),
                        "127.0.0.1",
                        "Result should contain the scanned IP"
                    );

                    // If port is open, it should be in the list
                    if !result.open_udp_ports.is_empty() {
                        prop_assert!(
                            result.open_udp_ports.contains(&port),
                            "Open port {} should be recorded in results",
                            port
                        );
                    }
                }

                Ok(())
            });
        }
    }
}


#[cfg(test)]
mod completeness_tests {
    use super::*;
    use crate::scanner::ARPScanner;

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
        fn prop_tcp_scan_results_include_all_required_fields(
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

                    // Must have open_tcp_ports list (even if empty)
                    let _ = &result.open_tcp_ports;

                    // Must have open_udp_ports list (even if empty)
                    let _ = &result.open_udp_ports;

                    // If this is a TCP scan result, open_tcp_ports should not be empty
                    prop_assert!(
                        !result.open_tcp_ports.is_empty(),
                        "TCP scan result should have at least one open port"
                    );
                }

                Ok(())
            });
        }

        #[test]
        fn prop_udp_scan_results_include_all_required_fields(
            port in prop::sample::select(vec![53u16, 123, 161]),
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let config = RateLimitConfig {
                    udp_rate: 1000,
                    ..Default::default()
                };
                let rate_limiter = Arc::new(RateLimiter::new(config));
            