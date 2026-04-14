#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

/// Device type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DeviceType {
    Router,
    Switch,
    Firewall,
    Server,
    Workstation,
    Printer,
    IoTDevice,
    Unknown,
}

/// Operating system family
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OsFamily {
    Windows,
    Linux,
    Unix,
    MacOS,
    NetworkOS,
    Unknown,
}

/// MAC address wrapper
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub fn new(bytes: [u8; 6]) -> Self {
        MacAddr(bytes)
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// Network interface status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InterfaceStatus {
    Up,
    Down,
    Unknown,
}

/// Network interface information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac: MacAddr,
    pub ip_addresses: Vec<IpAddr>,
    pub speed: Option<u64>,
    pub status: InterfaceStatus,
    pub vlan: Option<u16>,
}

/// Device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub hostname: String,
    pub device_type: DeviceType,
    pub os_family: OsFamily,
    pub os_version: Option<String>,
    pub open_ports: Vec<u16>,
    pub interfaces: Vec<NetworkInterface>,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub confidence: u8,
    pub performance_metrics: HashMap<String, f64>,
}

/// Routing table entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub destination: String, // Using String for IpNetwork representation
    pub gateway: IpAddr,
    pub interface: String,
    pub metric: u32,
}

/// ARP table entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub interface: String,
}

/// VLAN information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vlan {
    pub id: u16,
    pub name: String,
    pub devices: Vec<IpAddr>,
}

/// Switch port information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchPort {
    pub port_number: u32,
    pub connected_mac: MacAddr,
    pub vlan: u16,
    pub status: InterfaceStatus,
}
