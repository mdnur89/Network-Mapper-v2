#![allow(dead_code)]

use crate::models::{Device, MacAddr};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

/// Layer 2 topology information
#[derive(Debug, Clone)]
pub struct Layer2Topology {
    pub connections: HashMap<MacAddr, Vec<MacAddr>>,
    pub switch_ports: HashMap<MacAddr, Vec<crate::models::SwitchPort>>,
}

impl Layer2Topology {
    pub fn new() -> Self {
        Layer2Topology {
            connections: HashMap::new(),
            switch_ports: HashMap::new(),
        }
    }
}

impl Default for Layer2Topology {
    fn default() -> Self {
        Self::new()
    }
}

/// Layer 3 topology information
#[derive(Debug, Clone)]
pub struct Layer3Topology {
    pub connections: HashMap<IpAddr, Vec<IpAddr>>,
    pub routes: HashMap<IpAddr, Vec<crate::models::Route>>,
    pub subnets: Vec<String>, // Using String for IpNetwork representation
}

impl Layer3Topology {
    pub fn new() -> Self {
        Layer3Topology {
            connections: HashMap::new(),
            routes: HashMap::new(),
            subnets: Vec::new(),
        }
    }
}

impl Default for Layer3Topology {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete network topology
#[derive(Debug, Clone)]
pub struct NetworkTopology {
    pub devices: HashMap<IpAddr, Device>,
    pub layer2: Layer2Topology,
    pub layer3: Layer3Topology,
    pub vlans: HashMap<u16, crate::models::Vlan>,
    pub timestamp: std::time::SystemTime,
}

impl NetworkTopology {
    pub fn new() -> Self {
        NetworkTopology {
            devices: HashMap::new(),
            layer2: Layer2Topology::new(),
            layer3: Layer3Topology::new(),
            vlans: HashMap::new(),
            timestamp: std::time::SystemTime::now(),
        }
    }
}

impl Default for NetworkTopology {
    fn default() -> Self {
        Self::new()
    }
}

/// Security risk information
#[derive(Debug, Clone)]
pub struct SecurityRisk {
    pub risk_type: RiskType,
    pub severity: Severity,
    pub affected_device: IpAddr,
    pub description: String,
    pub remediation: String,
    pub detected_at: std::time::SystemTime,
}

/// Types of security risks
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskType {
    InsecureProtocol,
    DefaultCredentials,
    ExcessiveExposure,
    DeviceDisappeared,
    MacSpoofing,
    OutdatedOS,
    TopologyAnomaly,
    StealthDevice,
}

/// Risk severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Metric data point
#[derive(Debug, Clone)]
pub struct MetricPoint {
    pub timestamp: std::time::SystemTime,
    pub device: IpAddr,
    pub metric_name: String,
    pub value: f64,
}

/// Metrics storage with retention policy
#[derive(Debug)]
pub struct MetricsStore {
    metrics: HashMap<(IpAddr, String), Vec<MetricPoint>>,
    retention_period: std::time::Duration,
}

impl MetricsStore {
    pub fn new(retention_period: std::time::Duration) -> Self {
        MetricsStore {
            metrics: HashMap::new(),
            retention_period,
        }
    }

    pub fn add_metric(&mut self, point: MetricPoint) {
        let key = (point.device, point.metric_name.clone());
        self.metrics.entry(key).or_insert_with(Vec::new).push(point);
        self.prune_old_metrics();
    }

    pub fn get_metrics(&self, device: &IpAddr, metric_name: &str) -> Vec<MetricPoint> {
        let key = (*device, metric_name.to_string());
        self.metrics.get(&key).cloned().unwrap_or_default()
    }

    fn prune_old_metrics(&mut self) {
        let cutoff = std::time::SystemTime::now() - self.retention_period;
        for metrics in self.metrics.values_mut() {
            metrics.retain(|m| m.timestamp > cutoff);
        }
    }
}

/// Scan record for audit logging
#[derive(Debug, Clone)]
pub struct ScanRecord {
    pub scan_id: String,
    pub target: String,
    pub start_time: std::time::SystemTime,
    pub end_time: Option<std::time::SystemTime>,
    pub devices_discovered: usize,
    pub errors: Vec<String>,
}

/// Thread-safe shared data store for all network mapper data
#[derive(Debug, Clone)]
pub struct SharedDataStore {
    devices: Arc<RwLock<HashMap<IpAddr, Device>>>,
    topology: Arc<RwLock<NetworkTopology>>,
    metrics: Arc<RwLock<MetricsStore>>,
    risks: Arc<RwLock<Vec<SecurityRisk>>>,
    scan_history: Arc<RwLock<Vec<ScanRecord>>>,
}

impl SharedDataStore {
    /// Create a new empty data store
    pub fn new() -> Self {
        SharedDataStore {
            devices: Arc::new(RwLock::new(HashMap::new())),
            topology: Arc::new(RwLock::new(NetworkTopology::new())),
            metrics: Arc::new(RwLock::new(MetricsStore::new(
                std::time::Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            ))),
            risks: Arc::new(RwLock::new(Vec::new())),
            scan_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Update or insert a device
    pub fn update_device(&self, device: Device) {
        let mut devices = self.devices.write().unwrap();
        devices.insert(device.ip, device);
    }

    /// Get a device by IP address
    pub fn get_device(&self, ip: &IpAddr) -> Option<Device> {
        let devices = self.devices.read().unwrap();
        devices.get(ip).cloned()
    }

    /// Get all devices
    pub fn get_all_devices(&self) -> Vec<Device> {
        let devices = self.devices.read().unwrap();
        devices.values().cloned().collect()
    }

    /// Update the network topology
    pub fn update_topology(&self, topology: NetworkTopology) {
        let mut topo = self.topology.write().unwrap();
        *topo = topology;
    }

    /// Get the current network topology
    pub fn get_topology(&self) -> NetworkTopology {
        let topology = self.topology.read().unwrap();
        topology.clone()
    }

    /// Add a metric point
    pub fn add_metric(&self, point: MetricPoint) {
        let mut metrics = self.metrics.write().unwrap();
        metrics.add_metric(point);
    }

    /// Get metrics for a device
    pub fn get_metrics(&self, device: &IpAddr, metric_name: &str) -> Vec<MetricPoint> {
        let metrics = self.metrics.read().unwrap();
        metrics.get_metrics(device, metric_name)
    }

    /// Add a security risk
    pub fn add_risk(&self, risk: SecurityRisk) {
        let mut risks = self.risks.write().unwrap();
        risks.push(risk);
    }

    /// Get all security risks
    pub fn get_all_risks(&self) -> Vec<SecurityRisk> {
        let risks = self.risks.read().unwrap();
        risks.clone()
    }

    /// Clear all security risks
    pub fn clear_risks(&self) {
        let mut risks = self.risks.write().unwrap();
        risks.clear();
    }

    /// Add a scan record
    pub fn add_scan_record(&self, record: ScanRecord) {
        let mut history = self.scan_history.write().unwrap();
        history.push(record);
    }

    /// Get scan history
    pub fn get_scan_history(&self) -> Vec<ScanRecord> {
        let history = self.scan_history.read().unwrap();
        history.clone()
    }
}

impl Default for SharedDataStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DeviceType, OsFamily};
    use std::collections::HashMap;

    #[test]
    fn test_shared_data_store_device_operations() {
        let store = SharedDataStore::new();

        // Create a test device
        let device = Device {
            ip: "192.168.1.1".parse().unwrap(),
            mac: MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            hostname: "test-device".to_string(),
            device_type: DeviceType::Router,
            os_family: OsFamily::Linux,
            os_version: Some("5.0".to_string()),
            open_ports: vec![22, 80, 443],
            interfaces: vec![],
            first_seen: std::time::SystemTime::now(),
            last_seen: std::time::SystemTime::now(),
            confidence: 95,
            performance_metrics: HashMap::new(),
        };

        // Test update_device
        store.update_device(device.clone());

        // Test get_device
        let retrieved = store.get_device(&device.ip);
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.ip, device.ip);
        assert_eq!(retrieved.hostname, "test-device");
        assert_eq!(retrieved.confidence, 95);

        // Test get_all_devices
        let all_devices = store.get_all_devices();
        assert_eq!(all_devices.len(), 1);
    }

    #[test]
    fn test_shared_data_store_metrics() {
        let store = SharedDataStore::new();
        let device_ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Add a metric
        let metric = MetricPoint {
            timestamp: std::time::SystemTime::now(),
            device: device_ip,
            metric_name: "cpu_usage".to_string(),
            value: 45.5,
        };
        store.add_metric(metric);

        // Retrieve metrics
        let metrics = store.get_metrics(&device_ip, "cpu_usage");
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].value, 45.5);
    }

    #[test]
    fn test_shared_data_store_risks() {
        let store = SharedDataStore::new();
        let device_ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Add a risk
        let risk = SecurityRisk {
            risk_type: RiskType::InsecureProtocol,
            severity: Severity::High,
            affected_device: device_ip,
            description: "Telnet port open".to_string(),
            remediation: "Disable telnet and use SSH".to_string(),
            detected_at: std::time::SystemTime::now(),
        };
        store.add_risk(risk);

        // Get all risks
        let risks = store.get_all_risks();
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].severity, Severity::High);

        // Clear risks
        store.clear_risks();
        let risks = store.get_all_risks();
        assert_eq!(risks.len(), 0);
    }

    #[test]
    fn test_shared_data_store_scan_history() {
        let store = SharedDataStore::new();

        // Add a scan record
        let record = ScanRecord {
            scan_id: "scan-001".to_string(),
            target: "192.168.1.0/24".to_string(),
            start_time: std::time::SystemTime::now(),
            end_time: Some(std::time::SystemTime::now()),
            devices_discovered: 5,
            errors: vec![],
        };
        store.add_scan_record(record);

        // Get scan history
        let history = store.get_scan_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].scan_id, "scan-001");
        assert_eq!(history[0].devices_discovered, 5);
    }

    #[test]
    fn test_shared_data_store_thread_safety() {
        use std::thread;

        let store = SharedDataStore::new();
        let store_clone = store.clone();

        // Spawn a thread that adds devices
        let handle = thread::spawn(move || {
            for i in 0..10 {
                let device = Device {
                    ip: format!("192.168.1.{}", i).parse().unwrap(),
                    mac: MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, i as u8]),
                    hostname: format!("device-{}", i),
                    device_type: DeviceType::Unknown,
                    os_family: OsFamily::Unknown,
                    os_version: None,
                    open_ports: vec![],
                    interfaces: vec![],
                    first_seen: std::time::SystemTime::now(),
                    last_seen: std::time::SystemTime::now(),
                    confidence: 50,
                    performance_metrics: HashMap::new(),
                };
                store_clone.update_device(device);
            }
        });

        handle.join().unwrap();

        // Verify all devices were added
        let devices = store.get_all_devices();
        assert_eq!(devices.len(), 10);
    }
}
