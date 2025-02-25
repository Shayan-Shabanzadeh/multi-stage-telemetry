use pcap::Capture;
use pnet::packet::{Packet, ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, udp::UdpPacket};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use crate::count_min_sketch::CountMinSketch;
use crate::query_plan::QueryPlan;
use crate::packet_info::PacketInfo;
use crate::query_plan::execute_query;

/// Initializes the log file for writing.
fn initialize_log_file(path: &str) -> std::fs::File {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("Cannot open log file")
}

/// Processes a single packet, extracts information, and updates sketches and ground truth.
fn process_packet(
    packet: &pcap::Packet,
    query: &QueryPlan,
    threshold: usize,
    sketch: &mut CountMinSketch,
    ground_truth: &mut BTreeMap<String, usize>,
    packets_in_epoch: &mut Vec<String>,
) {
    let packet_timestamp = packet.header.ts.tv_sec as u64;

    if let Some(ethernet) = EthernetPacket::new(packet.data) {
        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                    let packet_info = PacketInfo {
                        src_ip: ipv4.get_source().to_string(),
                        dst_ip: ipv4.get_destination().to_string(),
                        src_port: udp.get_source(),
                        dst_port: udp.get_destination(),
                        tcp_flags: 0,
                    };

                    let packet_log = format!(
                        "Packet arrival timestamp: {} | src_ip: {}, dst_ip: {}, src_port: {}, dst_port: {}",
                        packet_timestamp, packet_info.src_ip, packet_info.dst_ip, packet_info.src_port, packet_info.dst_port
                    );

                    // ✅ Uncomment for detailed packet-level debugging.
                    // println!("{}", packet_log);

                    packets_in_epoch.push(packet_log);
                    execute_query(query, packet_info, threshold, sketch, ground_truth);
                }
            }
        }
    }
}

/// Logs epoch results, including ARE calculation, packet counts, and valid entries.
fn log_epoch_results(
    log_file: &mut std::fs::File,
    packets_in_epoch: &[String],
    ground_truth: &BTreeMap<String, usize>,
    sketch: &CountMinSketch,
    epoch_start: u64,
    epoch_end: u64,
    total_packets: usize,
    threshold: usize,
) {
    println!("\n========================= EPOCH RESULTS =========================");
    println!("Epoch start timestamp: {}", epoch_start);
    println!("Epoch end timestamp: {}", epoch_end);

    let mut log_output = String::new();
    let mut epoch_total_are = 0.0;
    let mut epoch_valid_entries = 0;

    for packet_log in packets_in_epoch {
        log_output.push_str(&format!("{}\n", packet_log));
    }

    for (combined_key, true_count) in ground_truth {
        if *true_count > threshold {
            let estimated_count = sketch.estimate(combined_key);
            let re = ((estimated_count as f64 - *true_count as f64).abs()) / (*true_count as f64);
            epoch_total_are += re;
            epoch_valid_entries += 1;

            let output = format!(
                "Detected DNS traffic: {} -> True: {}, Estimated: {}, RE: {:.4}",
                combined_key, true_count, estimated_count, re
            );
            println!("{}", output);
            log_output.push_str(&format!("{}\n", output));
        }
    }

    let avg_are = if epoch_valid_entries > 0 {
        epoch_total_are / epoch_valid_entries as f64
    } else {
        0.0
    };

    let summary = format!(
        "Average ARE for epoch: {:.4}\nTotal packets processed in epoch: {}\nValid entries counted: {}\nEpoch start timestamp: {}\nEpoch end timestamp: {}\n",
        avg_are, total_packets, epoch_valid_entries, epoch_start, epoch_end
    );

    println!("{}", summary);
    log_output.push_str(&summary);

    log_file
        .write_all(log_output.as_bytes())
        .expect("Failed to write to log file");
}

/// Handles the processing of the PCAP file, epochs, and logging.
pub fn process_pcap(file_path: &str, epoch_size: u64, threshold: usize, query: QueryPlan) {
    let mut cap = Capture::from_file(file_path).expect("Failed to open PCAP file");
    let mut sketch = CountMinSketch::new(1024, 600);
    let mut ground_truth: BTreeMap<String, usize> = BTreeMap::new();
    let mut packets_in_epoch: Vec<String> = Vec::new();
    let mut log_file = initialize_log_file("telemetry_log.txt");

    let mut current_epoch_start: Option<u64> = None;
    let mut first_packet_timestamp_in_epoch: Option<u64> = None;
    let mut last_packet_timestamp_in_epoch: Option<u64> = None;
    let mut total_packets = 0;

    while let Ok(packet) = cap.next_packet() {
        let packet_timestamp = packet.header.ts.tv_sec as u64;

        if current_epoch_start.is_none() {
            current_epoch_start = Some(packet_timestamp);
            first_packet_timestamp_in_epoch = Some(packet_timestamp);
        }

        first_packet_timestamp_in_epoch.get_or_insert(packet_timestamp);
        last_packet_timestamp_in_epoch = Some(packet_timestamp);
        total_packets += 1;

        process_packet(
            &packet,
            &query,
            threshold,
            &mut sketch,
            &mut ground_truth,
            &mut packets_in_epoch,
        );

        if packet_timestamp - current_epoch_start.unwrap() >= epoch_size {
            log_epoch_results(
                &mut log_file,
                &packets_in_epoch,
                &ground_truth,
                &sketch,
                first_packet_timestamp_in_epoch.unwrap(),
                last_packet_timestamp_in_epoch.unwrap(),
                total_packets,
                threshold,
            );

            sketch.clear();
            ground_truth.clear();
            packets_in_epoch.clear();

            current_epoch_start = Some(current_epoch_start.unwrap() + epoch_size);
            first_packet_timestamp_in_epoch = None;
            last_packet_timestamp_in_epoch = None;
            total_packets = 0;
        }
    }

    if let (Some(start), Some(end)) = (first_packet_timestamp_in_epoch, last_packet_timestamp_in_epoch) {
        log_epoch_results(
            &mut log_file,
            &packets_in_epoch,
            &ground_truth,
            &sketch,
            start,
            end,
            total_packets,
            threshold,
        );
    }
}
