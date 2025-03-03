use pcap::Capture;
use pnet::packet::{Packet, ethernet::EthernetPacket, ipv4::Ipv4Packet, tcp::TcpPacket};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use crate::count_min_sketch::CountMinSketch;

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
fn extract_packet_tuple(packet: &pcap::Packet) -> Option<(String, String, u16, u16, u8)> {
    let ethernet = EthernetPacket::new(packet.data)?;
    let ipv4 = Ipv4Packet::new(ethernet.payload())?;

    if ipv4.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
        TcpPacket::new(ipv4.payload()).map(|tcp| (
            ipv4.get_source().to_string(),
            ipv4.get_destination().to_string(),
            tcp.get_source(),
            tcp.get_destination(),
            tcp.get_flags(),
        ))
    } else {
        None
    }
}

/// Executes Query 1: TCP SYN packet detection and Count-Min Sketch updating.
fn execute_query_1(
    packet_tuple: (String, String, u16, u16, u8),
    sketch: &mut CountMinSketch,
    threshold: usize,
    ground_truth: &mut BTreeMap<String, u64>,
) {
    let (src_ip, _, _, _, tcp_flags) = packet_tuple;

    // Step 1: Filter only TCP SYN packets (tcp_flags == 2)
    if tcp_flags != 2 {
        return;
    }

    // Step 2: Map to (src_ip, 1) and update Count-Min Sketch
    sketch.increment(&src_ip, 1);
    let updated_count = sketch.estimate(&src_ip);
    *ground_truth.entry(src_ip.clone()).or_insert(0) = updated_count;
}

/// Prints and logs the epoch summary with all src_ip counts exceeding the threshold.
fn print_epoch_summary(
    timestamp: u64,
    total_packets: usize,
    threshold: usize,
    ground_truth: &BTreeMap<String, u64>,
    log_file: &mut std::fs::File,
) {
    let mut summary = format!(
        "\n=== EPOCH SUMMARY ===\nEpoch end timestamp: {}\nTotal packets processed: {}\n",
        timestamp, total_packets
    );

    let mut valid_entries = Vec::new();

    for (src_ip, &count) in ground_truth.iter().filter(|&(_, &count)| count > threshold as u64) {
        let entry = format!("(src_ip: {}, count: {})", src_ip, count);
        println!("{}", entry);
        summary.push_str(&format!("{}\n", entry));
        valid_entries.push(entry);
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
pub fn process_pcap(file_path: &str, epoch_size: u64, threshold: usize, query_id: u8) {
    let mut cap = Capture::from_file(file_path).expect("Failed to open PCAP file");
    let mut sketch = CountMinSketch::new(1024, 600);
    let mut log_file = initialize_log_file("telemetry_log.txt");
    let mut ground_truth: BTreeMap<String, u64> = BTreeMap::new();

    let mut total_packets = 0;
    let mut current_epoch_start: Option<u64> = None;

    while let Ok(packet) = cap.next_packet() {
        let packet_timestamp = packet.header.ts.tv_sec as u64;
        current_epoch_start.get_or_insert(packet_timestamp);

        if let Some(packet_tuple) = extract_packet_tuple(&packet) {
            match query_id {
                1 => execute_query_1(packet_tuple, &mut sketch, threshold, &mut ground_truth),
                _ => eprintln!("Invalid query ID: {}", query_id),
            }
        }

        total_packets += 1;

        // Epoch boundary: print summary if epoch size is reached
        if packet_timestamp - current_epoch_start.unwrap() >= epoch_size {
            print_epoch_summary(
                packet_timestamp,
                total_packets,
                threshold,
                &ground_truth,
                &mut log_file,
            );

            sketch.clear();
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
                &mut log_file,
            );
        }
    }
}
