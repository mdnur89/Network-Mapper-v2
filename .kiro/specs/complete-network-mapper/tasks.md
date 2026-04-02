# Implementation Plan: Complete Network Mapper

## Overview

This implementation plan breaks down the Complete Network Mapper into discrete, actionable tasks. The system includes 11 major components: Scanner Module, Device Fingerprinter, Protocol Handlers (SNMP/WMI/SSH), Topology Builder, Metrics Collector, Risk Detector, Report Generator, Topology Visualizer, Rate Limiter, and Shared Data Store. Each task builds incrementally, with checkpoints to validate progress.

## Tasks

- [ ] 1. Set up core data structures and shared data store
  - Create core data models (Device, NetworkInterface, MacAddr, Route, ArpEntry, Vlan, SwitchPort)
  - Implement SharedDataStore with thread-safe access using Arc<RwLock<>>
  - Add error types (ScanError, ProtocolError, MetricsError, ReportError)
  - Update DeviceType enum to derive Serialize, Deserialize, Clone
  - _Requirements: All requirements depend on these foundational structures_

- [ ] 2. Implement Rate Limiter component
  - [ ] 2.1 Create RateLimiter with token bucket algorithm for packet rate limiting
    - Implement TokenBucket struct with configurable packets per second
    - Add per-scan-type rate limits (ARP, ICMP, TCP, UDP)
    - Implement acquire_packet_permit() method with async waiting
    - _Requirements: 1.11, 10.1, 10.2, 10.3, 10.5_

  - [ ]* 2.2 Write property test for rate limiting enforcement
    - **Property 4: Rate Limiting Enforcement**
    - **Validates: Requirements 1.11, 10.1, 10.2, 10.3, 10.4**

  - [ ] 2.3 Add connection limiting with semaphore
    - Implement Semaphore-based concurrent connection limiting
    - Add acquire_connection_permit() method returning ConnectionPermit guard
    - _Requirements: 10.2, 10.4_

  - [ ] 2.4 Implement stealth mode with randomization
    - Add stealth_mode flag to reduce rate to 10%
    - Implement scan order randomization
    - Add random delays between probes
    - _Requirements: 10.6, 10.7_

  - [ ]* 2.5 Write property test for stealth mode behavior
    - **Property 67: Stealth Mode Rate Reduction**
    - **Property 68: Stealth Mode Randomization**
    - **Validates: Requirements 10.6, 10.7**

  - [ ] 2.6 Add whitelist and blacklist support
    - Implement IP whitelist exclusion logic
    - Implement IP blacklist prevention with logging
    - _Requirements: 10.8, 10.9, 10.10_

  - [ ]* 2.7 Write property tests for whitelist/blacklist
    - **Property 69: Whitelist Exclusion**
    - **Property 70: Blacklist Prevention**
    - **Validates: Requirements 10.8, 10.9, 10.10**


- [ ] 3. Implement Scanner Module
  - [ ] 3.1 Create Scanner trait and ScanTarget/ScanResult structures
    - Define Scanner trait with async scan() method
    - Create ScanTarget with network range and scan types
    - Create ScanResult with IP, MAC, ports, and timestamps
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.8, 1.10, 1.12_

  - [ ] 3.2 Implement ARPScanner for Layer 2 discovery
    - Use raw sockets to send ARP requests to all IPs in range
    - Record IP and MAC from ARP replies
    - Integrate with RateLimiter for packet rate control
    - _Requirements: 1.1, 1.2_

  - [ ]* 3.3 Write property test for scanner coverage completeness
    - **Property 1: Scanner Coverage Completeness**
    - **Validates: Requirements 1.1, 1.3, 1.6, 1.9**

  - [ ] 3.4 Implement ICMPScanner for Layer 3 discovery
    - Use raw sockets to send ICMP echo requests
    - Mark hosts as active on echo reply within 2s timeout
    - Mark hosts as filtered on destination unreachable
    - Integrate with RateLimiter
    - _Requirements: 1.3, 1.4, 1.5_

  - [ ] 3.5 Implement PortScanner for TCP port scanning
    - Probe TCP ports 1-1024 and common high ports (3389, 8080, 8443)
    - Use SYN scan technique with 1s timeout per port
    - Record open ports on SYN-ACK response
    - Integrate with RateLimiter
    - _Requirements: 1.6, 1.7, 1.8_

  - [ ]* 3.6 Write property test for scan operation timeout compliance
    - **Property 5: Scan Operation Timeout Compliance**
    - **Validates: Requirements 1.7, 3.12**

  - [ ] 3.7 Implement UDP port scanning
    - Probe UDP ports 53, 67, 68, 69, 123, 161, 162, 514
    - Send protocol-specific probes with 2s timeout
    - Record open ports on response
    - Integrate with RateLimiter
    - _Requirements: 1.9, 1.10_

  - [ ]* 3.8 Write property test for scan response recording
    - **Property 2: Scan Response Recording**
    - **Validates: Requirements 1.2, 1.4, 1.5, 1.8, 1.10**

  - [ ]* 3.9 Write property test for scan result completeness
    - **Property 3: Scan Result Completeness**
    - **Validates: Requirements 1.12**

  - [ ] 3.10 Integrate scanners with SharedDataStore
    - Store scan results in SharedDataStore
    - Update device records with scan timestamps
    - _Requirements: 1.12_

- [ ] 4. Checkpoint - Verify scanning functionality
  - Ensure all scanner tests pass, ask the user if questions arise.


- [ ] 5. Implement Device Fingerprinter
  - [ ] 5.1 Create DeviceFingerprinter with banner grabbing
    - Implement BannerGrabber for SSH (port 22), HTTP (80/443), Telnet (23)
    - Parse banners to extract OS and version information
    - _Requirements: 2.2, 2.3, 2.4, 2.6_

  - [ ]* 5.2 Write property test for fingerprinting trigger completeness
    - **Property 6: Fingerprinting Trigger Completeness**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5**

  - [ ]* 5.3 Write property test for banner parsing extraction
    - **Property 7: Banner Parsing Extraction**
    - **Validates: Requirements 2.6**

  - [ ] 5.4 Implement device classification rules
    - Windows detection: ports 135, 139, 445
    - Unix/Linux detection: ports 22, 111 without Windows ports
    - Web server detection: ports 80, 443, 8080, 8443 only
    - Network device detection: ports 161, 162 with many other ports
    - Printer detection: ports 515, 631, 9100
    - _Requirements: 2.7, 2.8, 2.9, 2.10, 2.11_

  - [ ]* 5.5 Write property test for device classification rules
    - **Property 8: Device Classification Rules**
    - **Validates: Requirements 2.7, 2.8, 2.9, 2.10, 2.11**

  - [ ] 5.6 Implement confidence scoring (0-100)
    - Calculate confidence based on port pattern matches
    - Assign higher confidence for unique patterns
    - _Requirements: 2.12_

  - [ ]* 5.7 Write property test for classification confidence scoring
    - **Property 9: Classification Confidence Scoring**
    - **Validates: Requirements 2.12**

  - [ ] 5.8 Mark devices as SNMP/SSH/WMI capable
    - Set snmp_capable flag when port 161 is open
    - Set ssh_capable flag when port 22 is open
    - Set wmi_capable flag when Windows ports are detected
    - _Requirements: 2.5, 2.7_

  - [ ] 5.9 Integrate fingerprinter with SharedDataStore
    - Update device profiles in SharedDataStore
    - Store DeviceProfile with type, OS, confidence
    - _Requirements: 2.1-2.12_

- [ ] 6. Implement Protocol Handlers
  - [ ] 6.1 Create ProtocolHandler trait and DeviceInfo structure
    - Define ProtocolHandler trait with async query() method
    - Create DeviceInfo with hostname, interfaces, routing, ARP tables
    - Add 10-second timeout for all protocol operations
    - _Requirements: 3.1-3.12_

  - [ ] 6.2 Implement SNMPHandler
    - Try "public" community string first, then alternatives
    - Query sysDescr, sysName, sysUpTime, ifTable
    - Query ipRouteTable and ipNetToMediaTable (ARP table)
    - Parse interface information (speed, status, MAC addresses)
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

  - [ ]* 6.3 Write property test for protocol handler conditional execution
    - **Property 10: Protocol Handler Conditional Execution**
    - **Validates: Requirements 3.1, 3.5, 3.8**

  - [ ]* 6.4 Write property test for SNMP query completeness
    - **Property 11: SNMP Query Completeness**
    - **Validates: Requirements 3.2, 3.4**

  - [ ]* 6.5 Write property test for SNMP community string fallback
    - **Property 12: SNMP Community String Fallback**
    - **Validates: Requirements 3.3**


  - [ ] 6.6 Implement WMIHandler for Windows devices
    - Query Win32_ComputerSystem, Win32_OperatingSystem, Win32_NetworkAdapter
    - Query Win32_IP4RouteTable for routing information
    - Extract hostname, OS version, domain membership, network interfaces
    - _Requirements: 3.5, 3.6, 3.7_

  - [ ]* 6.7 Write property test for WMI query completeness
    - **Property 13: WMI Query Completeness**
    - **Validates: Requirements 3.6, 3.7**

  - [ ] 6.8 Implement SSHHandler for Unix/Linux devices
    - Execute commands: hostname, uname -a, ip addr/ifconfig
    - Execute: ip route/netstat -rn, arp -a
    - Parse command output to extract system information
    - Handle command not found errors with fallback commands
    - _Requirements: 3.8, 3.9, 3.10_

  - [ ]* 6.9 Write property test for SSH command execution completeness
    - **Property 14: SSH Command Execution Completeness**
    - **Validates: Requirements 3.9, 3.10**

  - [ ] 6.10 Implement authentication failure handling
    - Log authentication failures without blocking
    - Continue with other protocols on failure
    - Mark protocol as unavailable for the device
    - _Requirements: 3.11_

  - [ ]* 6.11 Write property test for protocol handler error resilience
    - **Property 15: Protocol Handler Error Resilience**
    - **Validates: Requirements 3.11**

  - [ ] 6.12 Integrate protocol handlers with SharedDataStore
    - Store DeviceInfo in SharedDataStore
    - Update device records with protocol query results
    - _Requirements: 3.1-3.12_

- [ ] 7. Checkpoint - Verify protocol handler functionality
  - Ensure all protocol handler tests pass, ask the user if questions arise.

- [ ] 8. Implement Topology Builder
  - [ ] 8.1 Create TopologyBuilder with Layer2/Layer3 structures
    - Create NetworkTopology with devices, layer2, layer3, vlans
    - Create Layer2Topology with MAC connections and switch ports
    - Create Layer3Topology with IP connections, routes, subnets
    - _Requirements: 4.1-4.12_

  - [ ] 8.2 Implement Layer 2 topology construction
    - Create Layer2 entries from SNMP ifTable data
    - Map IP-to-MAC relationships from ARP tables
    - Create direct connections from CDP/LLDP neighbor data
    - _Requirements: 4.1, 4.2, 4.3_

  - [ ]* 8.3 Write property test for topology entry creation from interface data
    - **Property 16: Topology Entry Creation from Interface Data**
    - **Validates: Requirements 4.1, 4.2, 4.3**

  - [ ] 8.4 Implement Layer 3 topology construction
    - Create Layer3 entries for multi-interface devices on different subnets
    - Parse routing tables to create route entries
    - Infer hop-by-hop paths from traceroute data
    - _Requirements: 4.4, 4.5, 4.6, 4.7_

  - [ ]* 8.5 Write property test for multi-interface routing topology
    - **Property 17: Multi-Interface Routing Topology**
    - **Validates: Requirements 4.4**

  - [ ]* 8.6 Write property test for routing data topology construction
    - **Property 18: Routing Data Topology Construction**
    - **Validates: Requirements 4.5, 4.6, 4.7**


  - [ ] 8.7 Implement VLAN identification and grouping
    - Parse SNMP VLAN tables
    - Group devices by VLAN ID
    - Store VLAN information in topology
    - _Requirements: 4.9_

  - [ ]* 8.8 Write property test for VLAN identification and grouping
    - **Property 20: VLAN Identification and Grouping**
    - **Validates: Requirements 4.9**

  - [ ] 8.9 Implement Layer 2 loop detection
    - Identify redundant MAC address paths
    - Detect loops without spanning tree protocol
    - _Requirements: 4.8_

  - [ ]* 8.10 Write property test for Layer 2 loop detection
    - **Property 19: Layer 2 Loop Detection**
    - **Validates: Requirements 4.8**

  - [ ] 8.11 Implement topology inference for incomplete data
    - Infer connections from subnet membership
    - Use gateway configurations to infer routing
    - _Requirements: 4.10_

  - [ ]* 8.12 Write property test for topology inference from incomplete data
    - **Property 21: Topology Inference from Incomplete Data**
    - **Validates: Requirements 4.10**

  - [ ] 8.13 Implement incremental topology updates
    - Update topology without full rebuild on new scan data
    - Maintain current and historical topology states
    - _Requirements: 4.11, 4.12_

  - [ ]* 8.14 Write property test for incremental topology updates
    - **Property 22: Incremental Topology Updates**
    - **Validates: Requirements 4.11**

  - [ ]* 8.15 Write property test for topology state history maintenance
    - **Property 23: Topology State History Maintenance**
    - **Validates: Requirements 4.12**

  - [ ] 8.16 Integrate TopologyBuilder with SharedDataStore
    - Store topology in SharedDataStore
    - Provide read access for visualization and reporting
    - _Requirements: 4.1-4.12_

- [ ] 9. Implement Metrics Collector
  - [ ] 9.1 Create MetricsCollector and MetricsStore
    - Create MetricPoint with timestamp, device, metric name, value
    - Implement MetricsStore with retention policy (default 7 days)
    - Add metric types: CPU, memory, bandwidth, errors, packets
    - _Requirements: 5.1-5.12_

  - [ ] 9.2 Implement SNMP metrics collection
    - Query hrProcessorLoad for CPU usage
    - Query hrStorageUsed/hrStorageSize for memory
    - Query ifInOctets/ifOutOctets for bandwidth
    - Query ifInErrors/ifOutErrors for interface errors
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

  - [ ] 9.3 Implement WMI metrics collection
    - Query Win32_Processor.LoadPercentage for CPU
    - Query Win32_OperatingSystem.FreePhysicalMemory for memory
    - _Requirements: 5.5, 5.6_

  - [ ] 9.4 Implement SSH metrics collection
    - Parse top/vmstat output for CPU and memory
    - Parse netstat -i/ip -s link for interface statistics
    - _Requirements: 5.7, 5.8_

  - [ ]* 9.5 Write property test for conditional metrics collection
    - **Property 24: Conditional Metrics Collection**
    - **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8**


  - [ ] 9.6 Implement counter-based metrics delta calculation
    - Calculate deltas for bandwidth and packet count metrics
    - Store both raw and delta values
    - _Requirements: 5.9_

  - [ ]* 9.7 Write property test for counter-based metrics delta calculation
    - **Property 25: Counter-Based Metrics Delta Calculation**
    - **Validates: Requirements 5.9**

  - [ ] 9.8 Implement metric storage with timestamps
    - Store metrics with timestamp, device IP, metric name, value
    - Implement time-range queries
    - _Requirements: 5.10_

  - [ ]* 9.9 Write property test for metric storage completeness
    - **Property 26: Metric Storage Completeness**
    - **Validates: Requirements 5.10**

  - [ ] 9.10 Implement metrics retention policy
    - Prune metrics older than retention period
    - Run pruning periodically (every hour)
    - _Requirements: 5.11_

  - [ ]* 9.11 Write property test for metrics retention policy enforcement
    - **Property 27: Metrics Retention Policy Enforcement**
    - **Validates: Requirements 5.11**

  - [ ] 9.12 Implement metrics collection error handling
    - Log collection failures without blocking
    - Continue with other devices on error
    - _Requirements: 5.12_

  - [ ]* 9.13 Write property test for metrics collection error resilience
    - **Property 28: Metrics Collection Error Resilience**
    - **Validates: Requirements 5.12**

  - [ ] 9.14 Integrate MetricsCollector with SharedDataStore
    - Store metrics in SharedDataStore
    - Provide query interface for reports and visualization
    - _Requirements: 5.1-5.12_

- [ ] 10. Checkpoint - Verify topology and metrics functionality
  - Ensure all topology and metrics tests pass, ask the user if questions arise.

- [ ] 11. Implement Risk Detector
  - [ ] 11.1 Create RiskDetector with rule-based detection
    - Create SecurityRisk with type, severity, device, description, remediation
    - Define RiskType enum and Severity enum
    - Implement rule-based detection framework
    - _Requirements: 6.1-6.12_

  - [ ] 11.2 Implement port-based risk detection rules
    - Detect Telnet (port 23) as insecure protocol
    - Detect FTP (port 21) as insecure protocol
    - Detect RDP (port 3389) exposure to non-management networks
    - _Requirements: 6.1, 6.2, 6.5_

  - [ ]* 11.3 Write property test for port-based risk detection
    - **Property 29: Port-Based Risk Detection**
    - **Validates: Requirements 6.1, 6.2, 6.5**

  - [ ] 11.4 Implement configuration-based risk detection
    - Detect default SNMP community strings ("public", "private")
    - Detect SSH password authentication enabled
    - _Requirements: 6.3, 6.4_

  - [ ]* 11.5 Write property test for configuration-based risk detection
    - **Property 30: Configuration-Based Risk Detection**
    - **Validates: Requirements 6.3, 6.4**

  - [ ] 11.6 Implement threshold-based risk detection
    - Detect excessive open ports (>20 TCP ports)
    - _Requirements: 6.6_

  - [ ]* 11.7 Write property test for threshold-based risk detection
    - **Property 31: Threshold-Based Risk Detection**
    - **Validates: Requirements 6.6**


  - [ ] 11.8 Implement temporal risk detection
    - Detect devices not seen for 24 hours (Device Disappeared)
    - Track first_seen and last_seen timestamps
    - _Requirements: 6.7_

  - [ ]* 11.9 Write property test for temporal risk detection
    - **Property 32: Temporal Risk Detection**
    - **Validates: Requirements 6.7**

  - [ ] 11.10 Implement MAC-IP relationship risk detection
    - Track MAC-to-IP mappings over time
    - Detect MAC address appearing with different IP (MAC Spoofing)
    - _Requirements: 6.8_

  - [ ]* 11.11 Write property test for MAC-IP relationship risk detection
    - **Property 33: MAC-IP Relationship Risk Detection**
    - **Validates: Requirements 6.8**

  - [ ] 11.12 Implement OS version risk detection
    - Parse OS versions from banners
    - Flag outdated OS versions based on known EOL dates
    - _Requirements: 6.9_

  - [ ]* 11.13 Write property test for OS version risk detection
    - **Property 34: OS Version Risk Detection**
    - **Validates: Requirements 6.9**

  - [ ] 11.14 Implement topology-based risk detection
    - Detect Layer 2 loops without spanning tree
    - Use topology loop detection results
    - _Requirements: 6.10_

  - [ ]* 11.15 Write property test for topology-based risk detection
    - **Property 35: Topology-Based Risk Detection**
    - **Validates: Requirements 6.10**

  - [ ] 11.16 Implement scan pattern risk detection
    - Detect stealth devices (ICMP responsive but blocks TCP/UDP)
    - _Requirements: 6.11_

  - [ ]* 11.17 Write property test for scan pattern risk detection
    - **Property 36: Scan Pattern Risk Detection**
    - **Validates: Requirements 6.11**

  - [ ] 11.18 Implement risk severity assignment
    - Assign severity levels: Critical, High, Medium, Low
    - Use severity matrix based on risk type
    - _Requirements: 6.12_

  - [ ]* 11.19 Write property test for risk severity assignment
    - **Property 37: Risk Severity Assignment**
    - **Validates: Requirements 6.12**

  - [ ] 11.20 Integrate RiskDetector with SharedDataStore
    - Store detected risks in SharedDataStore
    - Provide query interface for reports and visualization
    - _Requirements: 6.1-6.12_

- [ ] 12. Implement Report Generator
  - [ ] 12.1 Create ReportGenerator with report structures
    - Create Report with inventory, topology summary, security findings, performance summary
    - Create DeviceInventoryEntry, TopologySummary, PerformanceSummary
    - Support ReportFormat: JSON, CSV, HTML
    - _Requirements: 7.1-7.12_

  - [ ] 12.2 Implement device inventory generation
    - Extract all devices from SharedDataStore
    - Include IP, MAC, hostname, device type, OS, open ports
    - _Requirements: 7.1, 7.2_

  - [ ]* 12.3 Write property test for device inventory entry completeness
    - **Property 39: Device Inventory Entry Completeness**
    - **Validates: Requirements 7.2**


  - [ ] 12.4 Implement topology summary generation
    - Calculate subnet counts from topology
    - Generate device type distribution statistics
    - Calculate connection statistics
    - _Requirements: 7.3, 7.4_

  - [ ]* 12.5 Write property test for topology summary content completeness
    - **Property 40: Topology Summary Content Completeness**
    - **Validates: Requirements 7.4**

  - [ ] 12.6 Implement security findings report
    - Extract all risks from SharedDataStore
    - Group risks by severity level
    - Include affected device details for each risk
    - _Requirements: 7.5, 7.6_

  - [ ]* 12.7 Write property test for security findings organization
    - **Property 41: Security Findings Organization**
    - **Validates: Requirements 7.6**

  - [ ] 12.8 Implement performance summary generation
    - Calculate average CPU, memory, bandwidth per device type
    - Query metrics from MetricsStore
    - _Requirements: 7.7, 7.8_

  - [ ]* 12.9 Write property test for performance summary content completeness
    - **Property 42: Performance Summary Content Completeness**
    - **Validates: Requirements 7.8**

  - [ ] 12.10 Implement JSON report format
    - Serialize Report structure to JSON
    - Use serde_json for serialization
    - _Requirements: 7.9_

  - [ ] 12.11 Implement CSV report format
    - Generate CSV for device inventory
    - Generate separate CSVs for security findings and metrics
    - _Requirements: 7.9_

  - [ ] 12.12 Implement HTML report format with embedded visualization
    - Generate HTML with CSS styling
    - Embed topology visualization as SVG or canvas
    - Include all report sections
    - _Requirements: 7.9, 7.10_

  - [ ]* 12.13 Write property test for report format support
    - **Property 43: Report Format Support**
    - **Validates: Requirements 7.9**

  - [ ]* 12.14 Write property test for HTML report visualization embedding
    - **Property 44: HTML Report Visualization Embedding**
    - **Validates: Requirements 7.10**

  - [ ] 12.15 Implement report metadata
    - Add generation timestamp
    - Calculate scan coverage percentage
    - _Requirements: 7.12_

  - [ ]* 12.16 Write property test for report metadata completeness
    - **Property 46: Report Metadata Completeness**
    - **Validates: Requirements 7.12**

  - [ ] 12.17 Optimize report generation performance
    - Ensure <5 second generation for 1000 devices
    - Use parallel processing where applicable
    - _Requirements: 7.11_

  - [ ]* 12.18 Write property test for report generation performance
    - **Property 45: Report Generation Performance**
    - **Validates: Requirements 7.11**

  - [ ]* 12.19 Write property test for report structure completeness
    - **Property 38: Report Structure Completeness**
    - **Validates: Requirements 7.1, 7.3, 7.5, 7.7**

- [ ] 13. Checkpoint - Verify risk detection and reporting functionality
  - Ensure all risk detection and report generation tests pass, ask the user if questions arise.


- [ ] 14. Implement Topology Visualizer GUI component
  - [ ] 14.1 Create TopologyVisualizer with egui rendering
    - Create TopologyVisualizer struct with layout engine
    - Add node_positions, selected_node, zoom_level, pan_offset
    - Implement render() method for egui
    - _Requirements: 8.1-8.12_

  - [ ] 14.2 Implement device node rendering
    - Render each device as a node in the GUI
    - Use different colors for different device types
    - Display IP address and hostname as labels
    - _Requirements: 8.1, 8.2, 8.3_

  - [ ]* 14.3 Write property test for device node rendering
    - **Property 47: Device Node Rendering**
    - **Validates: Requirements 8.1**

  - [ ]* 14.4 Write property test for device type visual differentiation
    - **Property 48: Device Type Visual Differentiation**
    - **Validates: Requirements 8.2**

  - [ ]* 14.5 Write property test for node label completeness
    - **Property 49: Node Label Completeness**
    - **Validates: Requirements 8.3**

  - [ ] 14.6 Implement connection line rendering
    - Render Layer 2 connections as solid lines
    - Render Layer 3 connections as dashed lines
    - _Requirements: 8.4, 8.5_

  - [ ]* 14.7 Write property test for connection rendering differentiation
    - **Property 50: Connection Rendering Differentiation**
    - **Validates: Requirements 8.4, 8.5**

  - [ ] 14.8 Implement risk visualization
    - Display warning icon on nodes with security risks
    - Use color coding for risk severity
    - _Requirements: 8.6_

  - [ ]* 14.9 Write property test for risk visualization
    - **Property 51: Risk Visualization**
    - **Validates: Requirements 8.6**

  - [ ] 14.10 Implement node interaction and detail panel
    - Handle node click events
    - Display device details in side panel
    - Show IP, MAC, hostname, OS, ports, metrics
    - _Requirements: 8.7_

  - [ ]* 14.11 Write property test for node interaction detail display
    - **Property 52: Node Interaction Detail Display**
    - **Validates: Requirements 8.7**

  - [ ] 14.12 Implement connection interaction
    - Handle connection line click events
    - Display connection details (bandwidth, latency, packet loss)
    - _Requirements: 8.8_

  - [ ]* 14.13 Write property test for connection interaction detail display
    - **Property 53: Connection Interaction Detail Display**
    - **Validates: Requirements 8.8**

  - [ ] 14.14 Implement zoom and pan controls
    - Add mouse wheel zoom support
    - Add click-and-drag pan support
    - Maintain zoom level and pan offset state
    - _Requirements: 8.9_

  - [ ]* 14.15 Write property test for visualization navigation support
    - **Property 54: Visualization Navigation Support**
    - **Validates: Requirements 8.9**

  - [ ] 14.16 Implement force-directed layout algorithm
    - Use spring-based force simulation
    - Position nodes automatically based on connections
    - Run layout algorithm iteratively until stable
    - _Requirements: 8.10_

  - [ ]* 14.17 Write property test for force-directed layout application
    - **Property 55: Force-Directed Layout Application**
    - **Validates: Requirements 8.10**


  - [ ] 14.18 Implement manual node positioning with persistence
    - Allow drag-and-drop node repositioning
    - Save positions to configuration file
    - Load saved positions on startup
    - _Requirements: 8.11_

  - [ ]* 14.19 Write property test for manual node positioning persistence
    - **Property 56: Manual Node Positioning Persistence**
    - **Validates: Requirements 8.11**

  - [ ] 14.20 Implement view position preservation on refresh
    - Maintain zoom level and pan offset during topology updates
    - Refresh display without resetting view
    - _Requirements: 8.12_

  - [ ]* 14.21 Write property test for view position preservation on refresh
    - **Property 57: View Position Preservation on Refresh**
    - **Validates: Requirements 8.12**

  - [ ] 14.22 Integrate visualizer with SharedDataStore
    - Read topology data from SharedDataStore
    - Subscribe to topology updates for real-time refresh
    - _Requirements: 8.1-8.12_

- [ ] 15. Implement comprehensive error handling
  - [ ] 15.1 Implement network operation error handling
    - Handle timeouts with logging and continuation
    - Handle connection refusals with logging
    - Handle network unreachable errors
    - _Requirements: 9.1, 9.2_

  - [ ]* 15.2 Write property test for network operation error resilience
    - **Property 58: Network Operation Error Resilience**
    - **Validates: Requirements 9.1, 9.2**

  - [ ] 15.3 Implement protocol handler failure resilience
    - Log authentication failures
    - Attempt alternative protocols on failure
    - Continue with other devices
    - _Requirements: 9.3_

  - [ ]* 15.4 Write property test for protocol handler failure resilience
    - **Property 59: Protocol Handler Failure Resilience**
    - **Validates: Requirements 9.3**

  - [ ] 15.5 Implement protocol-specific error handling
    - SNMP: Log error codes, continue with next query
    - SSH: Handle command not found, try alternatives
    - WMI: Handle class not found, access denied
    - _Requirements: 9.4, 9.5, 9.6_

  - [ ]* 15.6 Write property test for protocol-specific error handling
    - **Property 60: Protocol-Specific Error Handling**
    - **Validates: Requirements 9.4, 9.5, 9.6**

  - [ ] 15.7 Implement configuration error fallback
    - Use default values for missing/invalid config
    - Log warnings for configuration issues
    - _Requirements: 9.7_

  - [ ]* 15.8 Write property test for configuration error fallback
    - **Property 61: Configuration Error Fallback**
    - **Validates: Requirements 9.7**

  - [ ] 15.9 Implement invalid target rejection
    - Validate scan target format before scanning
    - Return error for invalid targets
    - Refuse to start scanning on invalid input
    - _Requirements: 9.8_

  - [ ]* 15.10 Write property test for invalid target rejection
    - **Property 62: Invalid Target Rejection**
    - **Validates: Requirements 9.8**

  - [ ] 15.11 Implement resource monitoring and response
    - Monitor memory usage every 10 seconds
    - Pause scanning if memory > 80%
    - Monitor disk space every 60 seconds
    - Rotate logs if disk space < 100MB
    - _Requirements: 9.9, 9.10_

  - [ ]* 15.12 Write property test for resource monitoring and response
    - **Property 63: Resource Monitoring and Response**
    - **Validates: Requirements 9.9, 9.10**


  - [ ] 15.13 Implement background task exception recovery
    - Catch unhandled exceptions in tokio tasks
    - Log stack traces with context
    - Restart tasks with exponential backoff
    - _Requirements: 9.11_

  - [ ]* 15.14 Write property test for background task exception recovery
    - **Property 64: Background Task Exception Recovery**
    - **Validates: Requirements 9.11**

  - [ ] 15.15 Implement component failure isolation
    - Ensure scanner component failures don't stop other components
    - Use separate tokio tasks for each component
    - _Requirements: 9.12_

  - [ ]* 15.16 Write property test for component failure isolation
    - **Property 65: Component Failure Isolation**
    - **Validates: Requirements 9.12**

- [ ] 16. Implement Network Mapper Orchestrator
  - [ ] 16.1 Create NetworkMapperOrchestrator
    - Coordinate all components (Scanner, Fingerprinter, Protocol Handlers, etc.)
    - Manage scan lifecycle with configurable intervals
    - Trigger periodic updates for topology, metrics, risks
    - _Requirements: All requirements_

  - [ ] 16.2 Implement scan workflow orchestration
    - Trigger Scanner with target networks
    - Pass scan results to Fingerprinter
    - Trigger Protocol Handlers based on device capabilities
    - Update Topology Builder with collected data
    - Trigger Metrics Collector for capable devices
    - Run Risk Detector on updated topology
    - _Requirements: 1.1-10.12_

  - [ ] 16.3 Implement periodic background tasks
    - Schedule scanning at configured intervals
    - Schedule metrics collection
    - Schedule risk detection
    - Schedule metrics pruning
    - _Requirements: 5.11, 9.9, 9.10_

  - [ ] 16.4 Implement authentication and authorization
    - Validate user credentials before scan operations
    - Load credentials from configuration
    - _Requirements: 10.11_

  - [ ]* 16.5 Write property test for authentication enforcement
    - **Property 71: Authentication Enforcement**
    - **Validates: Requirements 10.11**

  - [ ] 16.6 Implement audit logging
    - Log all scan activities with timestamps, targets, results
    - Use structured logging format
    - _Requirements: 10.12_

  - [ ]* 16.7 Write property test for audit logging completeness
    - **Property 72: Audit Logging Completeness**
    - **Validates: Requirements 10.12**

  - [ ] 16.8 Wire orchestrator with GUI
    - Connect orchestrator to NetworkMapperApp
    - Provide scan trigger from GUI buttons
    - Provide report generation trigger
    - _Requirements: 7.1-7.12, 8.1-8.12_

- [ ] 17. Update configuration management
  - [ ] 17.1 Extend AppConfig with all configuration options
    - Add RateLimitConfig with per-scan-type limits
    - Add CredentialsConfig with SNMP, WMI, SSH credentials
    - Add FeatureFlags for enabling/disabling protocols
    - Add RetentionConfig for metrics and logs
    - _Requirements: 3.1-3.12, 5.11, 10.1-10.12_

  - [ ] 17.2 Update config.toml with example configuration
    - Provide example values for all configuration options
    - Document each configuration parameter
    - _Requirements: All requirements_

  - [ ] 17.3 Implement configuration validation
    - Validate rate limits, credentials, network ranges
    - Use defaults for invalid values with warnings
    - _Requirements: 9.7_


- [ ] 18. Add required dependencies to Cargo.toml
  - [ ] 18.1 Add networking and protocol dependencies
    - Add pnet or socket2 for raw socket access (ARP, ICMP)
    - Add snmp crate for SNMP protocol
    - Add ssh2 or russh for SSH protocol
    - Add wmi crate for Windows Management Instrumentation
    - _Requirements: 1.1-1.12, 3.1-3.12_

  - [ ] 18.2 Add data structure and utility dependencies
    - Add ipnetwork for IP network range handling
    - Add mac_address or similar for MAC address handling
    - Add uuid for scan record IDs
    - Add thiserror for error type definitions
    - _Requirements: All requirements_

  - [ ] 18.3 Add testing dependencies
    - Add proptest for property-based testing
    - Add mockall for mocking in unit tests
    - Add criterion for benchmarking
    - _Requirements: Testing strategy_

  - [ ] 18.4 Add serialization and reporting dependencies
    - Add csv crate for CSV report generation
    - Add tera or askama for HTML template rendering
    - _Requirements: 7.9, 7.10_

- [ ] 19. Checkpoint - Verify complete system integration
  - Ensure all components are wired together, ask the user if questions arise.

- [ ] 20. Integration testing and validation
  - [ ] 20.1 Create integration test for end-to-end scan workflow
    - Test complete scan from target input to report generation
    - Use mock network devices
    - Verify all components execute correctly
    - _Requirements: All requirements_

  - [ ] 20.2 Create integration test for multi-protocol discovery
    - Test device with SNMP, WMI, and SSH capabilities
    - Verify all protocols are queried
    - Verify data is correctly aggregated
    - _Requirements: 3.1-3.12_

  - [ ] 20.3 Create integration test for topology construction
    - Test topology building from multi-device network
    - Verify Layer 2 and Layer 3 connections
    - Verify VLAN grouping and loop detection
    - _Requirements: 4.1-4.12_

  - [ ] 20.4 Create integration test for report generation
    - Generate all report formats (JSON, CSV, HTML)
    - Verify report completeness and correctness
    - Verify performance requirements (<5s for 1000 devices)
    - _Requirements: 7.1-7.12_

  - [ ] 20.5 Create integration test for GUI interaction
    - Simulate user interactions with topology visualizer
    - Verify node selection, zoom, pan
    - Verify detail panels display correctly
    - _Requirements: 8.1-8.12_

- [ ] 21. Performance optimization and benchmarking
  - [ ] 21.1 Benchmark scanning performance
    - Measure devices scanned per second
    - Optimize rate limiting implementation
    - Profile and optimize hot paths
    - _Requirements: 1.1-1.12, 10.1-10.7_

  - [ ] 21.2 Benchmark report generation performance
    - Verify <5 second generation for 1000 devices
    - Optimize data aggregation and formatting
    - Use parallel processing where applicable
    - _Requirements: 7.11_

  - [ ] 21.3 Benchmark GUI rendering performance
    - Measure frame rate for large topologies (100+ devices)
    - Optimize force-directed layout algorithm
    - Implement level-of-detail rendering if needed
    - _Requirements: 8.1-8.12_

  - [ ] 21.4 Profile memory usage
    - Monitor memory usage during large network scans
    - Optimize data structures for memory efficiency
    - Verify resource monitoring triggers correctly
    - _Requirements: 9.9_


- [ ] 22. Documentation and final polish
  - [ ] 22.1 Update README.md with usage instructions
    - Document installation and setup
    - Document configuration options
    - Provide usage examples
    - Document required privileges (raw sockets)
    - _Requirements: All requirements_

  - [ ] 22.2 Add inline documentation to all public APIs
    - Document all public structs, traits, and functions
    - Add usage examples in doc comments
    - Generate rustdoc documentation
    - _Requirements: All requirements_

  - [ ] 22.3 Create user guide for GUI
    - Document GUI features and controls
    - Explain topology visualization
    - Document report generation
    - _Requirements: 7.1-7.12, 8.1-8.12_

  - [ ] 22.4 Fix any remaining compiler warnings
    - Remove unused imports and variables
    - Fix DeviceType serialization issues
    - Ensure clean compilation
    - _Requirements: All requirements_

- [ ] 23. Final checkpoint - Complete system validation
  - Ensure all tests pass, all features work correctly, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional property-based tests and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at major milestones
- Property tests validate universal correctness properties (72 total properties)
- Unit tests validate specific examples and edge cases
- The implementation follows a bottom-up approach: foundational components first, then integration
- Raw socket operations (ARP, ICMP) require elevated privileges on most systems
- Some protocol handlers (WMI) are Windows-specific and may need conditional compilation
- The force-directed layout algorithm may need performance tuning for large networks (>100 devices)
- Consider using feature flags in Cargo.toml to make protocol handlers optional dependencies

