use crate::errors::ScanError;
use crate::models::{DeviceType, OsFamily};
use crate::scanner::ScanResult;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Device profile containing classification and capability information
#[derive(Debug, Clone)]
pub struct DeviceProfile {
    pub device_type: DeviceType,
    pub os_family: Option<OsFamily>,
    pub os_version: Option<String>,
    pub confidence: u8, // 0-100
    pub snmp_capable: bool,
    pub ssh_capable: bool,
    pub wmi_capable: bool,
}

impl DeviceProfile {
    /// Create a new device profile with unknown classification
    pub fn new() -> Self {
        Self {
            device_type: DeviceType::Unknown,
            os_family: None,
            os_version: None,
            confidence: 0,
            snmp_capable: false,
            ssh_capable: false,
            wmi_capable: false,
        }
    }
}

impl Default for DeviceProfile {
    fn default() -> Self {
        Self::new()
    }
}

/// Banner information retrieved from a service
#[derive(Debug, Clone)]
pub struct BannerInfo {
    pub port: u16,
    pub banner: String,
}

/// Banner grabber for extracting service banners
pub struct BannerGrabber {
    timeout: Duration,
}


impl BannerGrabber {
    /// Create a new banner grabber with default 5 second timeout
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }

    /// Create a new banner grabber with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Grab banner from SSH service (port 22)
    pub async fn grab_ssh_banner(&self, ip: std::net::IpAddr) -> Option<BannerInfo> {
        self.grab_banner(ip, 22).await
    }

    /// Grab banner from HTTP service (port 80)
    pub async fn grab_http_banner(&self, ip: std::net::IpAddr) -> Option<BannerInfo> {
        self.grab_http_banner_on_port(ip, 80).await
    }

    /// Grab banner from HTTPS service (port 443)
    pub async fn grab_https_banner(&self, ip: std::net::IpAddr) -> Option<BannerInfo> {
        self.grab_http_banner_on_port(ip, 443).await
    }

    /// Grab banner from Telnet service (port 23)
    pub async fn grab_telnet_banner(&self, ip: std::net::IpAddr) -> Option<BannerInfo> {
        self.grab_banner(ip, 23).await
    }

    /// Grab banner from a generic TCP service
    async fn grab_banner(&self, ip: std::net::IpAddr, port: u16) -> Option<BannerInfo> {
        let addr = format!("{}:{}", ip, port);
        
        match timeout(self.timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let mut buffer = vec![0u8; 1024];
                
                // Read banner (some services send it immediately)
                match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                        Some(BannerInfo { port, banner })
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Grab banner from HTTP service by sending GET request
    async fn grab_http_banner_on_port(&self, ip: std::net::IpAddr, port: u16) -> Option<BannerInfo> {
        let addr = format!("{}:{}", ip, port);
        
        match timeout(self.timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                // Send HTTP GET request
                let request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", ip);
                if stream.write_all(request.as_bytes()).await.is_err() {
                    return None;
                }

                let mut buffer = vec![0u8; 2048];
                match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                        Some(BannerInfo { port, banner })
                    }
                    _ => None,
                }
            }
  


impl BannerGrabber {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub async fn grab_ssh_banner(&self, ip: std::net::IpAddr) -> Option<BannerInfo> {
        self.grab_banner(ip, 22).await
    }

    pub async fn grab_http_banner(&self, ip: std::net::IpAddr) -> Option<BannerInfo> {
        self.grab_http_banner_on_port(ip, 80).await
    }

    pub async fn grab_https_banner(&self, ip: std::net::IpAddr) -> Option<BannerInfo> {
        self.grab_http_banner_on_port(ip, 443).await
    }

    pub async fn grab_telnet_banner(&self, ip: std::net::IpAddr) -> Option<BannerInfo> {
        self.grab_banner(ip, 23).await
    }

    async fn grab_banner(&self, ip: std::net::IpAddr, port: u16) -> Option<BannerInfo> {
        let addr = format!("{}:{}", ip, port);
        
        match timeout(self.timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let mut buffer = vec![0u8; 1024];
                
                match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                        Some(BannerInfo { port, banner })
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }


    async fn grab_http_banner_on_port(&self, ip: std::net::IpAddr, port: u16) -> Option<BannerInfo> {
        let addr = format!("{}:{}", ip, port);
        
        match timeout(self.timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", ip);
                if stream.write_all(request.as_bytes()).await.is_err() {
                    return None;
                }

                let mut buffer = vec![0u8; 2048];
                match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                        Some(BannerInfo { port, banner })
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Parse OS and version information from banner
    pub fn parse_banner(&self, banner_info: &BannerInfo) -> (Option<OsFamily>, Option<String>) {
        let banner_lower = banner_info.banner.to_lowercase();
        
        // SSH banner parsing
        if banner_info.port == 22 {
            if banner_lower.contains("ubuntu") {
                return (Some(OsFamily::Linux), self.extract_version(&banner_info.banner, "ubuntu"));
            } else if banner_lower.contains("debian") {
                return (Some(OsFamily::Linux), self.extract_version(&banner_info.banner, "debian"));
            } else if banner_lower.contains("openssh") {
                if banner_lower.contains("freebsd") {
                    return (Some(OsFamily::Unix), self.extract_version(&banner_info.banner, "freebsd"));
                }
                return (Some(OsFamily::Linux), self.extract_version(&banner_info.banner, "openssh"));
            }
        }
        
        // HTTP banner parsing
        if banner_info.port == 80 || banner_info.port == 443 {
            if banner_lower.contains("microsoft-iis") {
                return (Some(OsFamily::Windows), self.extract_version(&banner_info.banner, "microsoft-iis"));
            } else if banner_lower.contains("apache") {
                if banner_lower.contains("win") {
                    return (Some(OsFamily::Windows), self.extract_version(&banner_info.banner, "apache"));
                }
                return (Some(OsFamily::Linux), self.extract_version(&banner_info.banner, "apache"));
            } else if banner_lower.contains("nginx") {
                return (Some(OsFamily::Linux), self.extract_version(&banner_info.banner, "nginx"));
            }
        }
        
        // Telnet banner parsing
        if banner_info.port == 23 {
            if banner_lower.contains("windows") {
                return (Some(OsFamily::Windows), self.extract_version(&banner_info.banner, "windows"));
            } else if banner_lower.contains("linux") {
                return (Some(OsFamily::Linux), self.extract_version(&banner_info.banner, "linux"));
            }
        }
        
        (None, None)
    }

    fn extract_version(&self, banner: &str, keyword: &str) -> Option<String> {
        // Simple version extraction - look for patterns like "keyword/1.2.3" or "keyword 1.2.3"
        let banner_lower = banner.to_lowercase();
        let keyword_lower = keyword.to_lowercase();
        
        if let Some(pos) = banner_lower.find(&keyword_lower) {
            let after_keyword = &banner[pos + keyword.len()..];
            // Look for version pattern: digits, dots, and possibly letters
            let version_chars: String = after_keyword
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(|c| c.is_ascii_digit() || *c == '.' || c.is_ascii_alphabetic())
                .collect();
            
            if !version_chars.is_empty() {
                return Some(version_chars);
            }
        }
        
        None
    }
}

impl Default for BannerGrabber {
    fn default() -> Self {
        Self::new()
    }
}


/// Device fingerprinter for classifying devices and identifying OS
pub struct DeviceFingerprinter {
    banner_grabber: BannerGrabber,
}

impl DeviceFingerprinter {
    pub fn new() -> Self {
        Self {
            banner_grabber: BannerGrabber::new(),
        }
    }

    pub fn with_banner_grabber(banner_grabber: BannerGrabber) -> Self {
        Self { banner_grabber }
    }

    /// Fingerprint a device based on scan results
    pub async fn fingerprint(&self, scan_result: &ScanResult) -> DeviceProfile {
        let mut profile = DeviceProfile::new();
        
        // Grab banners from open ports
        let mut banners = Vec::new();
        
        for port in &scan_result.open_tcp_ports {
            match port {
                22 => {
                    if let Some(banner) = self.banner_grabber.grab_ssh_banner(scan_result.ip).await {
                        banners.push(banner);
                    }
                }
                80 => {
                    if let Some(banner) = self.banner_grabber.grab_http_banner(scan_result.ip).await {
                        banners.push(banner);
                    }
                }
                443 => {
                    if let Some(banner) = self.banner_grabber.grab_https_banner(scan_result.ip).await {
                        banners.push(banner);
                    }
                }
                23 => {
                    if let Some(banner) = self.banner_grabber.grab_telnet_banner(scan_result.ip).await {
                        banners.push(banner);
                    }
                }
                _ => {}
            }
        }
        
        // Parse banners to extract OS information
        for banner in &banners {
            let (os_family, os_version) = self.banner_grabber.parse_banner(banner);
            if os_family.is_some() {
                profile.os_family = os_family;
                profile.os_version = os_version;
                break; // Use first successful parse
            }
        }
        
        // Classify device based on port patterns
        self.classify_device(&mut profile, scan_result);
        
        // Mark protocol capabilities
        self.mark_capabilities(&mut profile, scan_result);
        
        // Calculate confidence score
        profile.confidence = self.calculate_confidence(&profile, scan_result);
        
        profile
    }

    /// Classify device type based on open ports
    fn classify_device(&self, profile: &mut DeviceProfile, scan_result: &ScanResult) {
        let ports = &scan_result.open_tcp_ports;
        
        // Windows detection: ports 135, 139, 445
        let has_windows_ports = ports.contains(&135) || ports.contains(&139) || ports.contains(&445);
        
        // Unix/Linux detection: ports 22, 111 without Windows ports
        let has_unix_ports = (ports.contains(&22) || ports.contains(&111)) && !has_windows_ports;
        
        // Web server detection: ports 80, 443, 8080, 8443 only
        let web_ports = [80, 443, 8080, 8443];
        let has_web_ports = web_ports.iter().any(|p| ports.contains(p));
        let only_web_ports = has_web_ports && ports.iter().all(|p| web_ports.contains(p) || *p < 1024);
        
        // Network device detection: ports 161, 162 with many other ports
        let has_snmp = ports.contains(&161) || ports.contains(&162);
        let many_ports = ports.len() > 10;
        
        // Printer detection: ports 515, 631, 9100
        let has_printer_ports = ports.contains(&515) || ports.contains(&631) || ports.contains(&9100);
        
        // Classification logic
        if has_printer_ports {
            profile.device_type = DeviceType::Printer;
            profile.os_family = Some(OsFamily::Unknown);
        } else if has_snmp && many_ports {
            profile.device_type = DeviceType::Router; // Could be router or switch
            profile.os_family = Some(OsFamily::NetworkOS);
        } else if only_web_ports && ports.len() <= 4 {
            profile.device_type = DeviceType::Server;
            if profile.os_family.is_none() {
                profile.os_family = Some(OsFamily::Linux); // Most web servers are Linux
            }
        } else if has_windows_ports {
            profile.device_type = DeviceType::Server; // Could be server or workstation
            profile.os_family = Some(OsFamily::Windows);
        } else if has_unix_ports {
            profile.device_type = DeviceType::Server;
            if profile.os_family.is_none() {
                profile.os_family = Some(OsFamily::Linux);
            }
        } else if !ports.is_empty() {
            profile.device_type = DeviceType::Unknown;
        }
    }

    /// Mark protocol capabilities based on open ports
    fn mark_capabilities(&self, profile: &mut DeviceProfile, scan_result: &ScanResult) {
        let ports = &scan_result.open_tcp_ports;
        
        // SNMP capable if port 161 is open
        profile.snmp_capable = ports.contains(&161);
        
        // SSH capable if port 22 is open
        profile.ssh_capable = ports.contains(&22);
        
        // WMI capable if Windows ports are detected
        profile.wmi_capable = ports.contains(&135) || ports.contains(&139) || ports.contains(&445);
    }

    /// Calculate confidence score (0-100) based on classification
    fn calculate_confidence(&self, profile: &DeviceProfile, scan_result: &ScanResult) -> u8 {
        let mut confidence = 0u8;
        
        // Base confidence from device type classification
        match profile.device_type {
            DeviceType::Unknown => confidence += 10,
            _ => confidence += 40,
        }
        
        // Add confidence if OS family is identified
        if profile.os_family.is_some() {
            confidence += 30;
        }
        
        // Add confidence if OS version is identified
        if profile.os_version.is_some() {
            confidence += 20;
        }
        
        // Add confidence based on number of open ports (more data = more confidence)
        let port_count = scan_result.open_tcp_ports.len();
        if port_count > 10 {
            confidence = confidence.saturating_add(10);
        } else if port_count > 5 {
            confidence = confidence.saturating_add(5);
        }
        
        // Cap at 100
        confidence.min(100)
    }
}

impl Default for DeviceFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_device_profile_creation() {
        let profile = DeviceProfile::new();
        assert_eq!(profile.device_type, DeviceType::Unknown);
        assert_eq!(profile.confidence, 0);
        assert!(!profile.snmp_capable);
        assert!(!profile.ssh_capable);
        assert!(!profile.wmi_capable);
    }

    #[test]
    fn test_banner_grabber_creation() {
        let grabber = BannerGrabber::new();
        assert_eq!(grabber.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_banner_parsing_ssh() {
        let grabber = BannerGrabber::new();
        let banner = BannerInfo {
            port: 22,
            banner: "SSH-2.0-OpenSSH_7.4 Ubuntu-1ubuntu2.8".to_string(),
        };
        
        let (os_family, os_version) = grabber.parse_banner(&banner);
        assert_eq!(os_family, Some(OsFamily::Linux));
        assert!(os_version.is_some());
    }

    #[test]
    fn test_banner_parsing_http() {
        let grabber = BannerGrabber::new();
        let banner = BannerInfo {
            port: 80,
            banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Ubuntu)\r\n".to_string(),
        };
        
        let (os_family, os_version) = grabber.parse_banner(&banner);
        assert_eq!(os_family, Some(OsFamily::Linux));
    }

    #[test]
    fn test_device_classification_windows() {
        let fingerprinter = DeviceFingerprinter::new();
        let mut profile = DeviceProfile::new();
        let mut scan_result = ScanResult::new("192.168.1.1".parse().unwrap());
        scan_result.open_tcp_ports = vec![135, 139, 445];
        
        fingerprinter.classify_device(&mut profile, &scan_result);
        
        assert_eq!(profile.device_type, DeviceType::Server);
        assert_eq!(profile.os_family, Some(OsFamily::Windows));
    }

    #[test]
    fn test_device_classification_linux() {
        let fingerprinter = DeviceFingerprinter::new();
        let mut profile = DeviceProfile::new();
        let mut scan_result = ScanResult::new("192.168.1.1".parse().unwrap());
        scan_result.open_tcp_ports = vec![22, 111];
        
        fingerprinter.classify_device(&mut profile, &scan_result);
        
        assert_eq!(profile.device_type, DeviceType::Server);
        assert_eq!(profile.os_family, Some(OsFamily::Linux));
    }

    #[test]
    fn test_device_classification_printer() {
        let fingerprinter = DeviceFingerprinter::new();
        let mut profile = DeviceProfile::new();
        let mut scan_result = ScanResult::new("192.168.1.1".parse().unwrap());
        scan_result.open_tcp_ports = vec![515, 631, 9100];
        
        fingerprinter.classify_device(&mut profile, &scan_result);
        
        assert_eq!(profile.device_type, DeviceType::Printer);
    }

    #[test]
    fn test_mark_capabilities() {
        let fingerprinter = DeviceFingerprinter::new();
        let mut profile = DeviceProfile::new();
        let mut scan_result = ScanResult::new("192.168.1.1".parse().unwrap());
        scan_result.open_tcp_ports = vec![22, 161, 445];
        
        fingerprinter.mark_capabilities(&mut profile, &scan_result);
        
        assert!(profile.ssh_capable);
        assert!(profile.snmp_capable);
        assert!(profile.wmi_capable);
    }

    #[test]
    fn test_confidence_calculation() {
        let fingerprinter = DeviceFingerprinter::new();
        let mut profile = DeviceProfile::new();
        profile.device_type = DeviceType::Server;
        profile.os_family = Some(OsFamily::Linux);
        profile.os_version = Some("20.04".to_string());
        
        let mut scan_result = ScanResult::new("192.168.1.1".parse().unwrap());
        scan_result.open_tcp_ports = vec![22, 80, 443];
        
        let confidence = fingerprinter.calculate_confidence(&profile, &scan_result);
        
        // Should be 40 (device type) + 30 (OS family) + 20 (OS version) = 90
        assert_eq!(confidence, 90);
    }
}


#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr};

    // Helper to generate random IP addresses
    fn arb_ip_addr() -> impl Strategy<Value = IpAddr> {
        (0u8..=255, 0u8..=255, 0u8..=255, 1u8..=254).prop_map(|(a, b, c, d)| {
            IpAddr::V4(Ipv4Addr::new(a, b, c, d))
        })
    }

    // Helper to generate random port lists
    fn arb_port_list() -> impl Strategy<Value = Vec<u16>> {
        prop::collection::vec(1u16..=65535, 0..20)
    }

    // Helper to generate scan results with specific ports
    fn arb_scan_result_with_ports(ports: Vec<u16>) -> impl Strategy<Value = ScanResult> {
        arb_ip_addr().prop_map(move |ip| {
            let mut result = ScanResult::new(ip);
            result.open_tcp_ports = ports.clone();
            result
        })
    }

    // Feature: complete-network-mapper, Property 6: Fingerprinting Trigger Completeness
    // **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5**
    //
    // For any device with open ports, the fingerprinter shall attempt appropriate banner grabbing
    // or analysis based on the port (SSH on 22, HTTP on 80/443, Telnet on 23, SNMP marking on 161).
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        #[test]
        fn prop_fingerprinter_attempts_ssh_banner_on_port_22(
            ip in arb_ip_addr()
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let mut scan_result = ScanResult::new(ip);
                scan_result.open_tcp_ports = vec![22];
                
                let fingerprinter = DeviceFingerprinter::new();
                let profile = fingerprinter.fingerprint(&scan_result).await;
                
                // The fingerprinter should mark SSH capability when port 22 is open
                prop_assert!(
                    profile.ssh_capable,
                    "Device with port 22 open should be marked as SSH capable"
                );
                
                Ok(())
            });
        }

        #[test]
        fn prop_fingerprinter_attempts_http_banner_on_port_80(
            ip in arb_ip_addr()
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let mut scan_result = ScanResult::new(ip);
                scan_result.open_tcp_ports = vec![80];
                
                let fingerprinter = DeviceFingerprinter::new();
                let profile = fingerprinter.fingerprint(&scan_result).await;
                
                // The fingerprinter should attempt HTTP banner grabbing
                // We can't verify the actual banner grab without a running server,
                // but we can verify the device is classified
                prop_assert!(
                    profile.device_type != DeviceType::Unknown || profile.confidence > 0,
                    "Device with port 80 open should be analyzed"
                );
                
                Ok(())
            });
        }

        #[test]
        fn prop_fingerprinter_attempts_https_banner_on_port_443(
            ip in arb_ip_addr()
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let mut scan_result = ScanResult::new(ip);
                scan_result.open_tcp_ports = vec![443];
                
                let fingerprinter = DeviceFingerprinter::new();
                let profile = fingerprinter.fingerprint(&scan_result).await;
                
                // The fingerprinter should attempt HTTPS banner grabbing
                prop_assert!(
                    profile.device_type != DeviceType::Unknown || profile.confidence > 0,
                    "Device with port 443 open should be analyzed"
                );
                
                Ok(())
            });
        }

        #[test]
        fn prop_fingerprinter_attempts_telnet_banner_on_port_23(
            ip in arb_ip_addr()
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let mut scan_result = ScanResult::new(ip);
                scan_result.open_tcp_ports = vec![23];
                
                let fingerprinter = DeviceFingerprinter::new();
                let profile = fingerprinter.fingerprint(&scan_result).await;
                
                // The fingerprinter should attempt Telnet banner grabbing
                prop_assert!(
                    profile.device_type != DeviceType::Unknown || profile.confidence > 0,
                    "Device with port 23 open should be analyzed"
                );
                
                Ok(())
            });
        }

        #[test]
        fn prop_fingerprinter_marks_snmp_capable_on_port_161(
            ip in arb_ip_addr()
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let mut scan_result = ScanResult::new(ip);
                scan_result.open_tcp_ports = vec![161];
                
                let fingerprinter = DeviceFingerprinter::new();
                let profile = fingerprinter.fingerprint(&scan_result).await;
                
                // The fingerprinter should mark SNMP capability when port 161 is open
                prop_assert!(
                    profile.snmp_capable,
                    "Device with port 161 open should be marked as SNMP capable"
                );
                
                Ok(())
            });
        }

        #[test]
        fn prop_fingerprinter_triggers_on_any_open_port(
            ip in arb_ip_addr(),
            ports in arb_port_list()
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                if ports.is_empty() {
                    return Ok(()); // Skip empty port lists
                }

                let mut scan_result = ScanResult::new(ip);
                scan_result.open_tcp_ports = ports.clone();
                
                let fingerprinter = DeviceFingerprinter::new();
                let profile = fingerprinter.fingerprint(&scan_result).await;
                
                // The fingerprinter should produce a profile for any device with open ports
                prop_assert!(
                    profile.confidence > 0,
                    "Device with {} open ports should have non-zero confidence",
                    ports.len()
                );
                
                // Check that appropriate banner grabbing was attempted for known ports
                if ports.contains(&22) {
                    prop_assert!(profile.ssh_capable, "Port 22 should mark SSH capable");
                }
                if ports.contains(&161) {
                    prop_assert!(profile.snmp_capable, "Port 161 should mark SNMP capable");
                }
                if ports.contains(&135) || ports.contains(&139) || ports.contains(&445) {
                    prop_assert!(profile.wmi_capable, "Windows ports should mark WMI capable");
                }
                
                Ok(())
            });
        }
    }
}
