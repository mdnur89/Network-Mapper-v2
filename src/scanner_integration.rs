use crate::data_store::SharedDataStore;
use crate::errors::ScanError;
use crate::models::{Device, DeviceType, MacAddr, OsFamily};
use crate::scanner::{ScanResult, ScanTarget, Scanner};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

/// Scanner that integrates with SharedDataStore
/// Wraps any scanner implementation and stores results in the data store
pub struct IntegratedScanner<S: Scanner> {
    scanner: S,
    data_store: Arc<SharedDataStore>,
}

impl<S: Scanner> IntegratedScanner<S> {
    /// Create a new integrated scanner
    pub fn new(scanner: S, data_store: Arc<SharedDataStore>) -> Self {
        Self {
            scanner,
            data_store,
        }
    }

    /// Store scan results in the data store
    fn store_results(&self, results: &[ScanResult]) {
        for result in results {
            // Check if device already exists
            let existing_device = self.data_store.get_device(&result.ip);

            let device = if let Some(mut device) = existing_device {
                // Update existing device
                device.last_seen = result.scan_timestamp;

                // Update MAC if we discovered it
                if let Some(mac) = result.mac {
                    device.mac = mac;
                }

                // Update ICMP responsiveness (not stored in Device model, but we could add it)
                // For now, we just update the timestamp

                // Merge open ports
                for port in &result.open_tcp_ports {
                    if !device.open_ports.contains(port) {
                        device.open_ports.push(*port);
                    }
                }

                for port in &result.open_udp_ports {
                    if !device.open_ports.contains(port) {
                        device.open_ports.push(*port);
                    }
                }

                // Sort ports for consistency
                device.open_ports.sort_unstable();

                device
            } else {
                // Create new device
                let mac = result.mac.unwrap_or_else(|| MacAddr::new([0, 0, 0, 0, 0, 0]));

                let mut open_ports = result.open_tcp_ports.clone();
                open_ports.extend_from_slice(&result.open_udp_ports);
                open_ports.sort_unstable();

                Device {
                    ip: result.ip,
                    mac,
                    hostname: String::new(), // Will be filled by fingerprinter
                    device_type: DeviceType::Unknown, // Will be filled by fingerprinter
                    os_family: OsFamily::Unknown, // Will be filled by fingerprinter
                    os_version: None,
                    open_ports,
                    interfaces: Vec::new(),
                    first_seen: result.scan_timestamp,
                    last_seen: result.scan_timestamp,
                    confidence: 0, // Will be filled by fingerprinter
                    performance_metrics: HashMap::new(),
                }
            };

            // Store the device
            self.data_store.update_device(device);
        }
    }
}

#[async_trait]
impl<S: Scanner> Scanner for IntegratedScanner<S> {
    async fn scan(&self, target: ScanTarget) -> Result<Vec<ScanResult>, ScanError> {
        // Perform the scan
        let results = self.scanner.scan(target).await?;

        // Store results in data store
        self.store_results(&results);

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limiter::{RateLimiter, RateLimitConfig};
    use crate::scanner::{ScanTypeVariant, Scanner};
    use crate::scanner_port::PortScanner;
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_integrated_scanner_stores_results() {
        let config = RateLimitConfig {
            tcp_rate: 1000,
            max_concurrent_connections: 100,
            ..Default::default()
        };
        let rate_limiter = Arc::new(RateLimiter::new(config));
        let scanner = PortScanner::new(rate_limiter);
        let data_store = Arc::new(SharedDataStore::new());

        let integrated = IntegratedScanner::new(scanner, data_store.clone());

        // Perform a scan
        let target = ScanTarget::new(
            "127.0.0.1/32".to_string(),
            vec![ScanTypeVariant::TCPPorts(vec![80, 443])],
        );

        let results = integrated.scan(target).await.unwrap();

        // If we got results, verify they're stored in the data store
        for result in results {
            let device = data_store.get_device(&result.ip);
            assert!(device.is_some(), "Device should be stored in data store");

            let device = device.unwrap();
            assert_eq!(device.ip, result.ip);

            // Verify open ports are stored
            for port in &result.open_tcp_ports {
                assert!(
                    device.open_ports.contains(port),
                    "Open port {} should be stored",
                    port
                );
            }
        }
    }

    #[tokio::test]
    async fn test_integrated_scanner_updates_existing_device() {
        let config = RateLimitConfig {
            tcp_rate: 1000,
            max_concurrent_connections: 100,
            ..Default::default()
        };
        let rate_limiter = Arc::new(RateLimiter::new(config));
        let scanner = PortScanner::new(rate_limiter);
        let data_store = Arc::new(SharedDataStore::new());

        // Create an existing device
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let existing_device = Device {
            ip,
            mac: MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            hostname: "existing".to_string(),
            device_type: DeviceType::Server,
            os_family: OsFamily::Linux,
            os_version: Some("5.0".to_string()),
            open_ports: vec![22],
            interfaces: Vec::new(),
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            confidence: 80,
            performance_metrics: HashMap::new(),
        };
        data_store.update_device(existing_device.clone());

        let integrated = IntegratedScanner::new(scanner, data_store.clone());

        // Perform a scan that might discover new ports
        let target = ScanTarget::new(
            "127.0.0.1/32".to_string(),
            vec![ScanTypeVariant::TCPPorts(vec![80])],
        );

        let _ = integrated.scan(target).await.unwrap();

        // Verify device was updated, not replaced
        let device = data_store.get_device(&ip).unwrap();
        assert_eq!(device.hostname, "existing", "Hostname should be preserved");
        assert_eq!(device.device_type, DeviceType::Server, "Device type should be preserved");
        assert_eq!(device.confidence, 80, "Confidence should be preserved");

        // last_seen should be updated
        assert!(device.last_seen >= existing_device.last_seen);
    }

    #[tokio::test]
    async fn test_integrated_scanner_merges_ports() {
        let config = RateLimitConfig {
            tcp_rate: 1000,
            max_concurrent_connections: 100,
            ..Default::default()
        };
        let rate_limiter = Arc::new(RateLimiter::new(config));
        let scanner = PortScanner::new(rate_limiter);
        let data_store = Arc::new(SharedDataStore::new());

        // Create an existing device with some ports
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let existing_device = Device {
            ip,
            mac: MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            hostname: "test".to_string(),
            device_type: DeviceType::Server,
            os_family: OsFamily::Linux,
            os_version: None,
            open_ports: vec![22, 80],
            interfaces: Vec::new(),
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            confidence: 50,
            performance_metrics: HashMap::new(),
        };
        data_store.update_device(existing_device);

        let integrated = IntegratedScanner::new(scanner, data_store.clone());

        // Scan for a different port
        let target = ScanTarget::new(
            "127.0.0.1/32".to_string(),
            vec![ScanTypeVariant::TCPPorts(vec![443])],
        );

        let results = integrated.scan(target).await.unwrap();

        // If port 443 was found open, it should be merged with existing ports
        if !results.is_empty() && results[0].open_tcp_ports.contains(&443) {
            let device = data_store.get_device(&ip).unwrap();
            
            // Should have original ports plus new one
            assert!(device.open_ports.contains(&22), "Original port 22 should be preserved");
            assert!(device.open_ports.contains(&80), "Original port 80 should be preserved");
            assert!(device.open_ports.contains(&443), "New port 443 should be added");
        }
    }

    #[tokio::test]
    async fn test_integrated_scanner_creates_new_device() {
        let config = RateLimitConfig {
            tcp_rate: 1000,
            max_concurrent_connections: 100,
            ..Default::default()
        };
        let rate_limiter = Arc::new(RateLimiter::new(config));
        let scanner = PortScanner::new(rate_limiter);
        let data_store = Arc::new(SharedDataStore::new());

        let integrated = IntegratedScanner::new(scanner, data_store.clone());

        // Verify data store is empty
        assert_eq!(data_store.get_all_devices().len(), 0);

        // Perform a scan
        let target = ScanTarget::new(
            "127.0.0.1/32".to_string(),
            vec![ScanTypeVariant::TCPPorts(vec![80])],
        );

        let results = integrated.scan(target).await.unwrap();

        // If we got results, a new device should be created
        if !results.is_empty() {
            let devices = data_store.get_all_devices();
            assert!(!devices.is_empty(), "New device should be created");

            let device = &devices[0];
            assert_eq!(device.ip.to_string(), "127.0.0.1");
            assert_eq!(device.device_type, DeviceType::Unknown);
            assert_eq!(device.os_family, OsFamily::Unknown);
        }
    }
}
