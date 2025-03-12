use procfs::process::Process;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Instant;
use sysinfo::{System, SystemExt};
use crate::sketch::Sketch;
use crate::query_plan::QueryPlan;
use crate::query_executor::{DynamicPacket, PacketField, execute_query, summarize_epoch};
use pcap::Capture;
use pnet::packet::{Packet, ethernet::EthernetPacket, ipv4::Ipv4Packet, tcp::TcpPacket};
use std::collections::HashMap;

/// Initializes and returns a writable log file.
fn initialize_log_file(path: &str) -> std::fs::File {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("Cannot open log file")
}

/// Extracts a `DynamicPacket` from the packet with fields: (src_ip, dst_ip, src_port, dst_port, tcp_flags, total_len, protocol, dns_ns_type)
fn extract_packet_tuple(packet: &pcap::Packet) -> Option<DynamicPacket> {
    let ethernet = EthernetPacket::new(packet.data)?;
    let ipv4 = Ipv4Packet::new(ethernet.payload())?;

    if ipv4.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
        let tcp = TcpPacket::new(ipv4.payload())?;
        Some(DynamicPacket::new(vec![
            PacketField::String(ipv4.get_source().to_string()),
            PacketField::String(ipv4.get_destination().to_string()),
            PacketField::U16(tcp.get_source()),
            PacketField::U16(tcp.get_destination()),
            PacketField::U8(tcp.get_flags()),
            PacketField::U16(ipv4.get_total_length()),
            PacketField::U8(ipv4.get_next_level_protocol().0),
            PacketField::OptionU16(None), // Initialize dns_ns_type with None
        ]))
    } else {
        None
    }
}

/// Gets the memory usage of the current process in KB.
fn get_process_memory_usage() -> u64 {
    let pid = std::process::id();
    let process = Process::new(pid as i32).expect("Failed to get process info");
    process.stat.vsize / 1024 // Convert from bytes to KB
}

/// Generates a key for the flow based on the non-zero and non-empty fields of the `DynamicPacket`.
/// Generates a key for the flow based on the non-zero and non-empty fields of the `DynamicPacket`.
fn generate_flow_key(packet: &DynamicPacket) -> (String, String, u16, u16, u8, u16, u8) {
    (
        match packet.get_field(0) {
            Some(PacketField::String(s)) => s.clone(),
            _ => "".to_string(),
        },
        match packet.get_field(1) {
            Some(PacketField::String(s)) => s.clone(),
            _ => "".to_string(),
        },
        match packet.get_field(2) {
            Some(PacketField::U16(v)) => *v,
            _ => 0,
        },
        match packet.get_field(3) {
            Some(PacketField::U16(v)) => *v,
            _ => 0,
        },
        match packet.get_field(4) {
            Some(PacketField::U8(v)) => *v,
            _ => 0,
        },
        match packet.get_field(5) {
            Some(PacketField::U16(v)) => *v,
            _ => 0,
        },
        match packet.get_field(6) {
            Some(PacketField::U8(v)) => *v,
            _ => 0,
        },
    )
}

/// Processes the PCAP file and executes the specified query in a streaming manner.
/// Runs the query line-rate, printing results as soon as conditions are met and providing epoch summaries.
pub fn process_pcap(file_path: &str, epoch_size: u64, query: QueryPlan) {
    println!("Starting packet processing...");
    let mut cap = Capture::from_file(file_path).expect("Failed to open PCAP file");
    let mut sketches: HashMap<String, Sketch> = HashMap::new();
    let mut log_file = initialize_log_file("telemetry_log.csv");
    let mut memory_log_file = initialize_log_file("memory_log.csv"); // New log file for memory usage
    let mut ground_truth: HashMap<String, u64> = HashMap::new();
    let mut flow_counts: HashMap<(String, String, u16, u16, u8, u16, u8), u64> = HashMap::new(); // Map to store flow counts

    let mut total_packets = 0;
    let mut epoch_packets = 0;
    let mut current_epoch_start: Option<u64> = None;
    let mut epoch_count = 0;

    // Initialize the system for memory usage tracking
    let mut sys = System::new();

    // Write header to memory log file
    if let Err(e) = writeln!(memory_log_file, "Epoch,Timestamp,ProcessMemoryUsedKB,TotalMemoryKB,AvailableMemoryKB") {
        eprintln!("Failed to write header to memory log file: {}", e);
    }

    // Start the timer
    let start_time = Instant::now();

    while let Ok(packet) = cap.next_packet() {
        // println!("Processing packet...");
        let packet_timestamp = packet.header.ts.tv_sec as u64;
        current_epoch_start.get_or_insert(packet_timestamp);

        if let Some(packet_info) = extract_packet_tuple(&packet) {
            let passed_flow = execute_query(&query, packet_info, &mut sketches, &mut ground_truth, &mut Vec::new());
            // println!("{:?}", passed_flow);
            if let Some(flow) = passed_flow {
                let flow_key = generate_flow_key(&flow);
                *flow_counts.entry(flow_key).or_insert(0) += 1;
            }
        }

        total_packets += 1;
        epoch_packets += 1;

        // Epoch boundary: print summary if epoch size is reached
        if packet_timestamp - current_epoch_start.unwrap() >= epoch_size {
            epoch_count += 1;
            sys.refresh_memory(); // Refresh memory usage
            let memory_used = get_process_memory_usage(); // Capture process-specific memory usage
            let total_memory = sys.total_memory();
            let available_memory = sys.available_memory();

            summarize_epoch(
                &query,
                packet_timestamp,
                epoch_packets,
                total_packets,
                &flow_counts,
                &mut log_file,
            );

            // Log memory usage to the new log file
            if let Err(e) = writeln!(memory_log_file, "{},{},{},{},{}", epoch_count, packet_timestamp, memory_used, total_memory, available_memory) {
                eprintln!("Failed to write memory usage to memory log file: {}", e);
            }

            sketches.values_mut().for_each(|sketch| sketch.clear());
            ground_truth.clear();
            flow_counts.clear(); // Clear the flow counts for the next epoch
            epoch_packets = 0;
            current_epoch_start = Some(packet_timestamp);
        }
    }

    // Final epoch summary for any remaining packets
    if let Some(epoch_start) = current_epoch_start {
        if epoch_packets > 0 {
            epoch_count += 1;
            sys.refresh_memory(); // Refresh memory usage
            let memory_used = get_process_memory_usage(); // Capture process-specific memory usage
            let total_memory = sys.total_memory();
            let available_memory = sys.available_memory();

            summarize_epoch(
                &query,
                epoch_start,
                epoch_packets,
                total_packets,
                &flow_counts,
                &mut log_file,
            );

            // Log memory usage to the new log file
            if let Err(e) = writeln!(memory_log_file, "{},{},{},{},{}", epoch_count, epoch_start, memory_used, total_memory, available_memory) {
                eprintln!("Failed to write memory usage to memory log file: {}", e);
            }
        }
    }

    // Stop the timer
    let elapsed_time = start_time.elapsed();
    let elapsed_seconds = elapsed_time.as_secs_f64();
    let packets_per_second = total_packets as f64 / elapsed_seconds;
    let average_packets_per_epoch = total_packets as f64 / epoch_count as f64;
    sys.refresh_memory(); // Refresh memory usage one last time
    let peak_memory = get_process_memory_usage();

    println!("Finished packet processing.");
    println!("Total packets processed: {}", total_packets);
    println!("Elapsed time: {:.2} seconds", elapsed_seconds);
    println!("Average packets per second: {:.2}", packets_per_second);
    println!("Average packets per epoch: {:.2}", average_packets_per_epoch);
    println!("Peak memory usage: {} KB", peak_memory);

    if let Err(e) = writeln!(log_file, "Total packets processed,Elapsed time (seconds),Average packets per second,Average packets per epoch,Peak memory usage (KB)\n{},{:.2},{:.2},{:.2},{}",
        total_packets, elapsed_seconds, packets_per_second, average_packets_per_epoch, peak_memory) {
        eprintln!("Failed to write performance metrics to log file: {}", e);
    } else {
        println!("Successfully wrote performance metrics to log file.");
    }
}