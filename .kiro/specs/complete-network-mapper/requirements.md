# Requirements Document

## Introduction

This document specifies the requirements for completing the Rust Network Mapper application. The application discovers devices on a network, identifies their types and characteristics, maps connections between them, collects performance metrics, detects security risks, and visualizes the network topology through a GUI. The current implementation has a basic skeleton with GUI (eframe/egui), async infrastructure (tokio), and configuration management, but requires implementation of core scanning, discovery, protocol handling, topology mapping, and reporting functionality.

## Glossary

- **Network_Mapper**: The complete application system that orchestrates scanning, discovery, topology mapping, and visualization
- **Scanner**: Component responsible for discovering devices on the network using various techniques (ARP, ICMP, TCP/UDP)
- **Device_Fingerprinter**: Component that identifies device types and operating systems based on scan results
- **Protocol_Handler**: Component that interrogates devices using specific protocols (SNMP, WMI, SSH)
- **Topology_Builder**: Component that constructs Layer 2 and Layer 3 network topology maps
- **Metrics_Collector**: Component that gathers performance data from discovered devices
- **Risk_Detector**: Component that identifies security vulnerabilities and misconfigurations
- **Report_Generator**: Component that produces network documentation and analysis reports
- **Topology_Visualizer**: GUI component that renders network topology graphically
- **Rate_Limiter**: Component that controls scanning speed to avoid network disruption
- **ARP_Scanner**: Scans using Address Resolution Protocol to discover Layer 2 devices
- **ICMP_Scanner**: Scans using Internet Control Message Protocol (ping) to discover active hosts
- **Port_Scanner**: Scans TCP and UDP ports to identify services
- **SNMP_Handler**: Queries devices using Simple Network Management Protocol
- **WMI_Handler**: Queries Windows devices using Windows Management Instrumentation
- **SSH_Handler**: Connects to devices via Secure Shell for information gathering
- **Layer2_Topology**: Network map showing MAC address connections (switches, VLANs)
- **Layer3_Topology**: Network map showing IP address routing relationships
- **Device**: A discovered network entity with IP address, MAC address, type, and characteristics
- **Performance_Metric**: Quantitative measurement of device health (CPU, memory, bandwidth, latency)
- **Security_Risk**: Identified vulnerability, misconfiguration, or policy violation
- **Scan_Target**: IP address range or subnet to be scanned

## Requirements

### Requirement 1: Network Scanning Capabilities

**User Story:** As a network administrator, I want to scan network ranges to discover active devices, so that I can build a complete inventory of my network infrastructure.

#### Acceptance Criteria

1. WHEN a Scan_Target is provided, THE ARP_Scanner SHALL send ARP requests to all addresses in the range
2. WHEN an ARP response is received, THE ARP_Scanner SHALL record the IP address and MAC address
3. WHEN a Scan_Target is provided, THE ICMP_Scanner SHALL send ICMP echo requests to all addresses in the range
4. WHEN an ICMP echo reply is received within 2 seconds, THE ICMP_Scanner SHALL mark the host as active
5. IF an ICMP destination unreachable is received, THEN THE ICMP_Scanner SHALL mark the host as filtered
6. WHEN an active host is discovered, THE Port_Scanner SHALL probe TCP ports 1-1024 and common high ports (3389, 8080, 8443)
7. WHEN a TCP port is probed, THE Port_Scanner SHALL complete the connection attempt within 1 second
8. WHEN a TCP SYN-ACK is received, THE Port_Scanner SHALL record the port as open
9. WHEN an active host is discovered, THE Port_Scanner SHALL probe UDP ports 53, 67, 68, 69, 123, 161, 162, 514
10. WHEN a UDP port is probed and a response is received within 2 seconds, THE Port_Scanner SHALL record the port as open
11. FOR ALL scanning operations, THE Scanner SHALL respect the configured Rate_Limiter settings
12. WHEN scanning completes for a Scan_Target, THE Scanner SHALL return a list of discovered devices with IP, MAC, and open ports

### Requirement 2: Device Discovery and Fingerprinting

**User Story:** As a network administrator, I want discovered devices to be automatically identified and classified, so that I can understand what types of equipment are on my network.

#### Acceptance Criteria

1. WHEN a Device has open ports, THE Device_Fingerprinter SHALL analyze the port combination to infer device type
2. WHEN TCP port 22 is open, THE Device_Fingerprinter SHALL attempt SSH banner grabbing
3. WHEN TCP port 80 or 443 is open, THE Device_Fingerprinter SHALL attempt HTTP header analysis
4. WHEN TCP port 23 is open, THE Device_Fingerprinter SHALL attempt telnet banner grabbing
5. WHEN UDP port 161 is open, THE Device_Fingerprinter SHALL mark the device as SNMP-capable
6. WHEN banner information is retrieved, THE Device_Fingerprinter SHALL parse it to identify operating system and version
7. WHEN ports 135, 139, 445 are open, THE Device_Fingerprinter SHALL classify the device as Windows-based
8. WHEN ports 22, 111 are open without Windows ports, THE Device_Fingerprinter SHALL classify the device as Unix-based
9. WHEN ports 80, 443, 8080, 8443 are open with no other services, THE Device_Fingerprinter SHALL classify the device as a web server
10. WHEN ports 161, 162 are open with many other ports, THE Device_Fingerprinter SHALL classify the device as a network device (router or switch)
11. WHEN ports 515, 631, 9100 are open, THE Device_Fingerprinter SHALL classify the device as a printer
12. THE Device_Fingerprinter SHALL assign a confidence score (0-100) to each device type classification

### Requirement 3: Protocol Handler Implementation

**User Story:** As a network administrator, I want the system to query devices using standard management protocols, so that I can gather detailed configuration and status information.

#### Acceptance Criteria

1. WHERE SNMP is enabled, WHEN a Device is marked as SNMP-capable, THE SNMP_Handler SHALL query the device using SNMPv2c community string "public"
2. WHERE SNMP is enabled, WHEN SNMP query succeeds, THE SNMP_Handler SHALL retrieve sysDescr, sysName, sysUpTime, and ifTable
3. WHERE SNMP is enabled, IF SNMP query fails with "public", THEN THE SNMP_Handler SHALL attempt configured alternative community strings
4. WHERE SNMP is enabled, WHEN SNMP data is retrieved, THE SNMP_Handler SHALL parse interface information including speed, status, and MAC addresses
5. WHERE WMI is enabled, WHEN a Device is classified as Windows-based, THE WMI_Handler SHALL attempt WMI connection using configured credentials
6. WHERE WMI is enabled, WHEN WMI connection succeeds, THE WMI_Handler SHALL query Win32_ComputerSystem, Win32_OperatingSystem, and Win32_NetworkAdapter
7. WHERE WMI is enabled, WHEN WMI data is retrieved, THE WMI_Handler SHALL extract hostname, OS version, domain membership, and network interfaces
8. WHERE SSH is enabled, WHEN a Device has port 22 open, THE SSH_Handler SHALL attempt SSH connection using configured credentials
9. WHERE SSH is enabled, WHEN SSH connection succeeds, THE SSH_Handler SHALL execute commands: "hostname", "uname -a", "ip addr" or "ifconfig"
10. WHERE SSH is enabled, WHEN command output is received, THE SSH_Handler SHALL parse the output to extract hostname, OS information, and interface details
11. FOR ALL protocol handlers, IF authentication fails, THEN THE Protocol_Handler SHALL log the failure and continue without blocking other operations
12. FOR ALL protocol handlers, THE Protocol_Handler SHALL complete operations within 10 seconds or timeout

### Requirement 4: Topology Discovery and Mapping

**User Story:** As a network administrator, I want the system to map how devices are connected, so that I can understand my network structure and troubleshoot connectivity issues.

#### Acceptance Criteria

1. WHEN SNMP data includes ifTable with multiple interfaces, THE Topology_Builder SHALL create Layer2_Topology entries for each interface
2. WHEN ARP tables are retrieved via SNMP or SSH, THE Topology_Builder SHALL map IP-to-MAC relationships
3. WHEN CDP or LLDP neighbor information is available via SNMP, THE Topology_Builder SHALL create direct Layer2_Topology connections between devices
4. WHEN a Device has multiple network interfaces on different subnets, THE Topology_Builder SHALL create Layer3_Topology entries for routing relationships
5. WHEN traceroute data is available, THE Topology_Builder SHALL infer Layer3_Topology hop-by-hop paths
6. WHEN a Device is identified as a router or firewall, THE Topology_Builder SHALL query routing tables via SNMP or SSH
7. WHEN routing table data is retrieved, THE Topology_Builder SHALL create Layer3_Topology entries for each route
8. THE Topology_Builder SHALL detect Layer 2 loops by identifying redundant MAC address paths
9. THE Topology_Builder SHALL identify VLANs from SNMP VLAN tables and group devices accordingly
10. WHEN topology data is incomplete, THE Topology_Builder SHALL infer connections based on subnet membership and gateway configurations
11. THE Topology_Builder SHALL update topology maps incrementally as new scan data becomes available
12. FOR ALL topology operations, THE Topology_Builder SHALL maintain both current and historical topology states for change detection

### Requirement 5: Performance Metrics Collection

**User Story:** As a network administrator, I want to collect performance metrics from devices, so that I can monitor network health and identify performance bottlenecks.

#### Acceptance Criteria

1. WHERE metrics collection is enabled, WHEN a Device supports SNMP, THE Metrics_Collector SHALL query CPU usage (hrProcessorLoad)
2. WHERE metrics collection is enabled, WHEN a Device supports SNMP, THE Metrics_Collector SHALL query memory usage (hrStorageUsed/hrStorageSize)
3. WHERE metrics collection is enabled, WHEN a Device supports SNMP, THE Metrics_Collector SHALL query interface bandwidth (ifInOctets/ifOutOctets)
4. WHERE metrics collection is enabled, WHEN a Device supports SNMP, THE Metrics_Collector SHALL query interface errors (ifInErrors/ifOutErrors)
5. WHERE metrics collection is enabled, WHEN a Device supports WMI, THE Metrics_Collector SHALL query Win32_Processor LoadPercentage
6. WHERE metrics collection is enabled, WHEN a Device supports WMI, THE Metrics_Collector SHALL query Win32_OperatingSystem FreePhysicalMemory
7. WHERE metrics collection is enabled, WHEN a Device supports SSH, THE Metrics_Collector SHALL parse "top" or "vmstat" output for CPU and memory
8. WHERE metrics collection is enabled, WHEN a Device supports SSH, THE Metrics_Collector SHALL parse "netstat -i" or "ip -s link" for interface statistics
9. WHEN metrics are collected, THE Metrics_Collector SHALL calculate delta values for counter-based metrics (bandwidth, packet counts)
10. WHEN metrics are collected, THE Metrics_Collector SHALL store timestamp, device IP, metric name, and metric value
11. THE Metrics_Collector SHALL retain metrics for the configured retention period (default 7 days)
12. WHEN metric collection fails, THE Metrics_Collector SHALL log the error and continue with other devices

### Requirement 6: Security Risk Detection

**User Story:** As a security analyst, I want the system to identify security risks and vulnerabilities, so that I can prioritize remediation efforts.

#### Acceptance Criteria

1. WHEN a Device has TCP port 23 (telnet) open, THE Risk_Detector SHALL flag it as "Insecure Protocol - Telnet"
2. WHEN a Device has TCP port 21 (FTP) open, THE Risk_Detector SHALL flag it as "Insecure Protocol - FTP"
3. WHEN a Device has SNMP community string "public" or "private", THE Risk_Detector SHALL flag it as "Default SNMP Community"
4. WHEN a Device has TCP port 22 open with password authentication enabled, THE Risk_Detector SHALL flag it as "SSH Password Authentication"
5. WHEN a Device has TCP port 3389 (RDP) exposed to non-management networks, THE Risk_Detector SHALL flag it as "RDP Exposure"
6. WHEN a Device has more than 20 open TCP ports, THE Risk_Detector SHALL flag it as "Excessive Open Ports"
7. WHEN a Device has not been seen in scans for 24 hours after initial discovery, THE Risk_Detector SHALL flag it as "Device Disappeared"
8. WHEN a Device appears with a MAC address previously associated with a different IP, THE Risk_Detector SHALL flag it as "Possible MAC Spoofing"
9. WHEN a Device has outdated OS version based on banner information, THE Risk_Detector SHALL flag it as "Outdated Operating System"
10. WHEN Layer2_Topology shows a loop without spanning tree protocol, THE Risk_Detector SHALL flag it as "Layer 2 Loop Detected"
11. WHEN a Device responds to ICMP but blocks all TCP/UDP probes, THE Risk_Detector SHALL flag it as "Stealth Device"
12. THE Risk_Detector SHALL assign severity levels (Critical, High, Medium, Low) to each identified risk

### Requirement 7: Report Generation

**User Story:** As a network administrator, I want to generate comprehensive reports, so that I can document my network and share findings with stakeholders.

#### Acceptance Criteria

1. WHEN report generation is requested, THE Report_Generator SHALL create a device inventory listing all discovered devices
2. WHEN generating device inventory, THE Report_Generator SHALL include IP, MAC, hostname, device type, OS, and open ports for each device
3. WHEN report generation is requested, THE Report_Generator SHALL create a topology summary describing network structure
4. WHEN generating topology summary, THE Report_Generator SHALL include subnet counts, device type distribution, and connection statistics
5. WHEN report generation is requested, THE Report_Generator SHALL create a security findings report listing all identified risks
6. WHEN generating security findings, THE Report_Generator SHALL group risks by severity and include affected device details
7. WHEN report generation is requested, THE Report_Generator SHALL create a performance summary with average metrics per device type
8. WHEN generating performance summary, THE Report_Generator SHALL include CPU, memory, and bandwidth utilization statistics
9. THE Report_Generator SHALL support output formats: JSON, CSV, and HTML
10. WHEN HTML format is selected, THE Report_Generator SHALL include embedded topology visualization
11. WHEN report generation is requested, THE Report_Generator SHALL complete within 5 seconds for networks up to 1000 devices
12. THE Report_Generator SHALL include report generation timestamp and scan coverage percentage

### Requirement 8: Topology Visualization

**User Story:** As a network administrator, I want to see a visual representation of my network topology, so that I can quickly understand network structure and relationships.

#### Acceptance Criteria

1. WHEN the GUI is displayed, THE Topology_Visualizer SHALL render discovered devices as nodes
2. WHEN rendering device nodes, THE Topology_Visualizer SHALL use different colors for different device types (routers, switches, servers, endpoints)
3. WHEN rendering device nodes, THE Topology_Visualizer SHALL display device IP address and hostname as labels
4. WHEN Layer2_Topology connections exist, THE Topology_Visualizer SHALL render them as solid lines between nodes
5. WHEN Layer3_Topology connections exist, THE Topology_Visualizer SHALL render them as dashed lines between nodes
6. WHEN a device has security risks, THE Topology_Visualizer SHALL display a warning icon on the node
7. WHEN a user clicks on a device node, THE Topology_Visualizer SHALL display detailed device information in a side panel
8. WHEN a user clicks on a connection line, THE Topology_Visualizer SHALL display connection details (bandwidth, latency, packet loss)
9. THE Topology_Visualizer SHALL support zoom and pan operations for large networks
10. THE Topology_Visualizer SHALL use force-directed layout algorithm to position nodes automatically
11. WHERE user preferences allow, THE Topology_Visualizer SHALL support manual node repositioning with position persistence
12. THE Topology_Visualizer SHALL refresh the display when topology data is updated without losing user's current view position

### Requirement 9: Error Handling and Resilience

**User Story:** As a network administrator, I want the system to handle errors gracefully, so that scanning continues even when individual operations fail.

#### Acceptance Criteria

1. WHEN a network operation times out, THE Network_Mapper SHALL log the timeout and continue with the next operation
2. WHEN a device refuses connection, THE Network_Mapper SHALL log the refusal and mark the port as closed
3. WHEN authentication fails for a Protocol_Handler, THE Network_Mapper SHALL log the failure and attempt other protocols
4. WHEN SNMP query returns an error, THE SNMP_Handler SHALL log the error code and continue without blocking
5. WHEN SSH connection fails, THE SSH_Handler SHALL log the failure reason and mark the device as SSH-unavailable
6. WHEN WMI connection fails, THE WMI_Handler SHALL log the failure and mark the device as WMI-unavailable
7. IF the configuration file is missing or invalid, THEN THE Network_Mapper SHALL use default configuration values and log a warning
8. IF the scan target network range is invalid, THEN THE Network_Mapper SHALL return an error message and refuse to start scanning
9. WHEN memory usage exceeds 80% of available memory, THE Network_Mapper SHALL pause scanning and log a warning
10. WHEN disk space for logs falls below 100MB, THE Network_Mapper SHALL rotate logs and delete oldest entries
11. WHEN an unhandled exception occurs in a background task, THE Network_Mapper SHALL log the stack trace and restart the task
12. THE Network_Mapper SHALL maintain operation even when individual scanner components fail

### Requirement 10: Rate Limiting and Security Controls

**User Story:** As a network administrator, I want to control scanning intensity, so that I don't disrupt network operations or trigger security alerts.

#### Acceptance Criteria

1. THE Rate_Limiter SHALL enforce a configurable maximum packets per second limit (default 100 pps)
2. THE Rate_Limiter SHALL enforce a configurable maximum concurrent connections limit (default 50 connections)
3. WHEN the packet rate exceeds the configured limit, THE Rate_Limiter SHALL delay subsequent packets to maintain the limit
4. WHEN the concurrent connection limit is reached, THE Rate_Limiter SHALL queue new connection attempts
5. THE Rate_Limiter SHALL support different rate limits for different scan types (ARP, ICMP, TCP, UDP)
6. WHERE stealth mode is enabled, THE Rate_Limiter SHALL reduce scanning speed to 10% of normal rate
7. WHERE stealth mode is enabled, THE Scanner SHALL randomize scan order and introduce random delays between probes
8. THE Network_Mapper SHALL support IP address whitelist to exclude sensitive devices from scanning
9. THE Network_Mapper SHALL support IP address blacklist to prevent scanning of external or unauthorized networks
10. WHEN a blacklisted IP is encountered, THE Network_Mapper SHALL skip it and log a warning
11. WHERE authentication is required, THE Network_Mapper SHALL validate user credentials before allowing scan operations
12. THE Network_Mapper SHALL log all scan activities with timestamps, targets, and results for audit purposes

