use rust_network_mapper::rate_limiter::{RateLimitConfig, RateLimiter, ScanType};

#[tokio::main]
async fn main() {
    println!("Rate Limiter Demo\n");

    // Create a rate limiter with custom configuration
    let config = RateLimitConfig {
        max_packets_per_second: 100,
        max_concurrent_connections: 50,
        arp_rate: 50,
        icmp_rate: 100,
        tcp_rate: 75,
        udp_rate: 25,
        stealth_mode: false,
    };

    let limiter = RateLimiter::new(config);

    println!("Testing packet rate limiting...");
    println!("Acquiring 3 permits for each scan type:");

    println!("  ARP permits (rate: 50 pps)...");
    for _ in 0..3 {
        limiter.acquire_packet_permit(ScanType::ARP).await;
    }
    println!("    ✓ 3 ARP permits acquired");

    println!("  ICMP permits (rate: 100 pps)...");
    for _ in 0..3 {
        limiter.acquire_packet_permit(ScanType::ICMP).await;
    }
    println!("    ✓ 3 ICMP permits acquired");

    println!("  TCP permits (rate: 75 pps)...");
    for _ in 0..3 {
        limiter.acquire_packet_permit(ScanType::TCP).await;
    }
    println!("    ✓ 3 TCP permits acquired");

    println!("  UDP permits (rate: 25 pps)...");
    for _ in 0..3 {
        limiter.acquire_packet_permit(ScanType::UDP).await;
    }
    println!("    ✓ 3 UDP permits acquired");

    println!("\nTesting connection limiting...");
    println!("Acquiring 3 connection permits (max: 50 concurrent):");

    let mut permits = Vec::new();
    for i in 0..3 {
        let permit = limiter.acquire_connection_permit().await;
        println!("  ✓ Connection permit {} acquired", i + 1);
        permits.push(permit);
    }

    println!("\n✓ All tests passed!");
    println!("Permits will be released when they go out of scope.");
}
