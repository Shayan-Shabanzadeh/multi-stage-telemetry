use pcap::Capture;
use pnet::packet::{Packet, ethernet::EthernetPacket, ipv4::Ipv4Packet, tcp::TcpPacket};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use crate::sketch::Sketch;
use crate::query_plan::{QueryPlan};
use crate::query_executor::execute_query;
use crate::packet_info::PacketInfo;

/// Initializes and returns a writable log file.
fn initialize_log_file(path: &str) -> std::fs::File {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("Cannot open log file")
}

/// Extracts a tuple from the packet with fields: (src_ip, dst_ip, src_port, dst_port, tcp_flags)
fn extract_packet_tuple(packet: &pcap::Packet) -> Option<PacketInfo> {
    let ethernet = EthernetPacket::new(packet.data)?;
    let ipv4 = Ipv4Packet::new(ethernet.payload())?;

    if ipv4.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
        TcpPacket::new(ipv4.payload()).map(|tcp| PacketInfo {
            src_ip: ipv4.get_source().to_string(),
            dst_ip: ipv4.get_destination().to_string(),
            src_port: tcp.get_source(),
            dst_port: tcp.get_destination(),
            tcp_flags: tcp.get_flags(),
        })
    } else {
        None
    }
}

/// Prints and logs the epoch summary with all src_ip counts exceeding the threshold.
fn print_epoch_summary(
    timestamp: u64,
    total_packets: usize,
    threshold: usize,
    ground_truth: &HashMap<String, u64>,
    sketches: &HashMap<String, Sketch>,
    log_file: &mut std::fs::File,
) {
    let mut summary = format!(
        "\n=== EPOCH SUMMARY ===\nEpoch end timestamp: {}\nTotal packets processed: {}\n",
        timestamp, total_packets
    );

    let mut valid_entries: Vec<(String, u64, u64)> = ground_truth.iter()
        .filter(|&(_, &count)| count > threshold as u64)
        .map(|(src_ip, &real_count)| {
            let estimated_count = sketches.values().map(|sketch| sketch.estimate(src_ip)).max().unwrap_or(0);
            (src_ip.clone(), real_count, estimated_count)
        })
        .collect();

    // Sort by estimated count in descending order
    valid_entries.sort_by(|a, b| b.2.cmp(&a.2));

    for (src_ip, real_count, estimated_count) in &valid_entries {
        let entry = format!("(src_ip: {}, real_count: {}, estimated_count: {})", src_ip, real_count, estimated_count);
        println!("{}", entry);
        summary.push_str(&format!("{}\n", entry));
    }

    if valid_entries.is_empty() {
        summary.push_str("No entries exceeded the threshold.\n");
    }

    if let Err(e) = writeln!(log_file, "{}", summary.trim_end()) {
        eprintln!("Failed to write to log file: {}", e);
    }
}

/// Processes the PCAP file and executes the specified query in a streaming manner.
/// Runs the query line-rate, printing results as soon as conditions are met and providing epoch summaries.
pub fn process_pcap(file_path: &str, epoch_size: u64, threshold: usize, query: QueryPlan, seed: u64) {
    println!("Starting packet processing...");
    let mut cap = Capture::from_file(file_path).expect("Failed to open PCAP file");
    let mut sketches: HashMap<String, Sketch> = HashMap::new();
    let mut log_file = initialize_log_file("telemetry_log.txt");
    let mut ground_truth: HashMap<String, u64> = HashMap::new();

    let mut total_packets = 0;
    let mut current_epoch_start: Option<u64> = None;

    while let Ok(packet) = cap.next_packet() {
        // println!("Processing packet...");
        let packet_timestamp = packet.header.ts.tv_sec as u64;
        current_epoch_start.get_or_insert(packet_timestamp);

        if let Some(packet_info) = extract_packet_tuple(&packet) {
            execute_query(&query, packet_info, threshold, &mut sketches, &mut ground_truth);
        }

        total_packets += 1;

        // Epoch boundary: print summary if epoch size is reached
        if packet_timestamp - current_epoch_start.unwrap() >= epoch_size {
            print_epoch_summary(
                packet_timestamp,
                total_packets,
                threshold,
                &ground_truth,
                &sketches,
                &mut log_file,
            );

            sketches.values_mut().for_each(|sketch| sketch.clear());
            ground_truth.clear();
            total_packets = 0;
            current_epoch_start = Some(packet_timestamp);
        }
    }

    // Final epoch summary for any remaining packets
    if let Some(epoch_start) = current_epoch_start {
        if total_packets > 0 {
            print_epoch_summary(
                epoch_start,
                total_packets,
                threshold,
                &ground_truth,
                &sketches,
                &mut log_file,
            );
        }
    }
    println!("Finished packet processing.");
}