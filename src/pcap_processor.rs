use procfs::process::Process;
use std::fs::OpenOptions;
use std::io::Write;
use lazy_static::lazy_static; // Import the lazy_static macro
use std::sync::Mutex;
use std::time::Instant;
use sysinfo::{System, SystemExt};
use crate::sketch::Sketch;
use crate::query_plan::{QueryPlan};
use crate::query_executor::{PacketField, execute_query};
use pcap::Capture;
use pnet::packet::{Packet, ethernet::EthernetPacket, ipv4::Ipv4Packet, tcp::TcpPacket};
use std::collections::HashMap;


lazy_static! {
    pub static ref EPOCH_RESULTS: Mutex<Vec<HashMap<String, PacketField>>> = Mutex::new(Vec::new());
}


/// Initializes and returns a writable log file.
fn initialize_log_file(path: &str) -> std::fs::File {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("Cannot open log file")
}

/// Extracts a packet tuple as a `HashMap`.
fn extract_packet_tuple(packet: &pcap::Packet) -> Option<HashMap<String, PacketField>> {
    let ethernet = EthernetPacket::new(packet.data)?;
    let ipv4 = Ipv4Packet::new(ethernet.payload())?;

    if ipv4.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
        let tcp = TcpPacket::new(ipv4.payload())?;
        let mut packet_map = HashMap::new();
        packet_map.insert("src_ip".to_string(), PacketField::String(ipv4.get_source().to_string()));
        packet_map.insert("dst_ip".to_string(), PacketField::String(ipv4.get_destination().to_string()));
        packet_map.insert("src_port".to_string(), PacketField::U16(tcp.get_source()));
        packet_map.insert("dst_port".to_string(), PacketField::U16(tcp.get_destination()));
        packet_map.insert("tcp_flags".to_string(), PacketField::U8(tcp.get_flags()));
        packet_map.insert("total_len".to_string(), PacketField::U16(ipv4.get_total_length()));
        packet_map.insert("protocol".to_string(), PacketField::U8(ipv4.get_next_level_protocol().0));
        packet_map.insert("dns_ns_type".to_string(), PacketField::OptionU16(None));
        Some(packet_map)
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

/// Prints and logs the epoch summary with all src_ip counts exceeding the threshold.
fn print_epoch_summary(
    timestamp: u64,
    epoch_packets: usize,
    total_packets: usize,
    threshold: usize,
    ground_truth: &HashMap<String, (u64, u64)>,
    sketches: &HashMap<String, Sketch>,
    log_file: &mut std::fs::File,
) {
    println!("Printing epoch summary...");
    let mut summary = format!(
        "\n=== EPOCH SUMMARY ===\nEpoch end timestamp: {}\nPackets processed this epoch: {}\nTotal packets processed: {}\n",
        timestamp, epoch_packets, total_packets
    );

    let mut valid_entries: Vec<(String, u64, u64)> = ground_truth.iter()
        .filter(|&(_, &(real_count, estimated_count))| estimated_count > threshold as u64)
        .map(|(key, &(real_count, estimated_count))| {
            (key.clone(), real_count, estimated_count)
        })
        .collect();

    // Sort by real count in descending order
    valid_entries.sort_by(|a, b| b.1.cmp(&a.1));

    summary.push_str("Flow key,real_count,estimated_count\n");
    for (key, real_count, estimated_count) in &valid_entries {
        let entry = format!("{},{},{}\n", key, real_count, estimated_count);
        summary.push_str(&entry);
    }

    if valid_entries.is_empty() {
        summary.push_str("No entries exceeded the threshold.\n");
    }

    if let Err(e) = writeln!(log_file, "{}", summary.trim_end()) {
        eprintln!("Failed to write to log file: {}", e);
    } else {
        println!("Successfully wrote to log file."); // Debugging statement
    }
}
/// Processes the PCAP file and executes the specified query in a feed forwarding manner.
pub fn process_pcap(file_path: &str, epoch_size: u64, threshold: usize, query: QueryPlan) {
    println!("Starting packet processing...");
    let mut cap = Capture::from_file(file_path).expect("Failed to open PCAP file");
    let mut sketches: HashMap<String, Sketch> = HashMap::new();
    let mut log_file = initialize_log_file("telemetry_log.csv");
    let mut memory_log_file = initialize_log_file("memory_log.csv");
    let mut ground_truth: HashMap<String, (u64, u64)> = HashMap::new();

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
        let packet_timestamp = packet.header.ts.tv_sec as u64;
        current_epoch_start.get_or_insert(packet_timestamp);

        if let Some(packet_info) = extract_packet_tuple(&packet) {
            execute_query(
                &query,
                packet_info,
                &mut sketches,
                &mut ground_truth,
                epoch_size,  
                &mut current_epoch_start,  
                packet_timestamp,         
            );
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

            print_epoch_summary(
                packet_timestamp,
                epoch_packets,
                total_packets,
                threshold,
                &ground_truth,
                &sketches,
                &mut log_file,
            );

            // Log memory usage to the new log file
            if let Err(e) = writeln!(memory_log_file, "{},{},{},{},{}", epoch_count, packet_timestamp, memory_used, total_memory, available_memory) {
                eprintln!("Failed to write memory usage to memory log file: {}", e);
            }

            sketches.values_mut().for_each(|sketch| sketch.clear());
            ground_truth.clear();
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

            print_epoch_summary(
                epoch_start,
                epoch_packets,
                total_packets,
                threshold,
                &ground_truth,
                &sketches,
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
    let peak_memory = get_process_memory_usage(); // Capture peak memory usage of the process

    println!("Finished packet processing.");
    println!("Total packets processed: {}", total_packets);
    println!("Elapsed time: {:.2} seconds", elapsed_seconds);
    println!("Average packets per second: {:.2}", packets_per_second);
    println!("Average packets per epoch: {:.2}", average_packets_per_epoch);
    println!("Peak memory usage: {} KB", peak_memory); // ✅ Peak memory

    if let Err(e) = writeln!(log_file, "\n=== PERFORMANCE METRICS ===\nTotal packets processed: {}\nElapsed time: {:.2} seconds\nAverage packets per second: {:.2}\nAverage packets per epoch: {:.2}\nPeak memory usage: {} KB\n",
        total_packets, elapsed_seconds, packets_per_second, average_packets_per_epoch, peak_memory) {
        eprintln!("Failed to write performance metrics to log file: {}", e);
    } else {
        println!("Successfully wrote performance metrics to log file.");
    }
}