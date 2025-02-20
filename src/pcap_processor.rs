use pcap::Capture;
use pnet::packet::{Packet, ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use crate::query_parser::parse_query;
use crate::query_executor::execute_query;
use crate::packet_info::PacketInfo;
use crate::count_min_sketch::CountMinSketch;

pub fn process_pcap(file_path: &str, epoch_size: u64, threshold: usize) {
    let mut cap = Capture::from_file(file_path).expect("Failed to open PCAP file");
    let mut current_epoch_start = Instant::now();
    let mut total_packets = 0;

    let query = parse_query();
    let mut sketch = CountMinSketch::new(1024, 600);
    let mut ground_truth: HashMap<String, usize> = HashMap::new();

    let log_file_path = "telemetry_log.txt";
    let mut log_file = OpenOptions::new().write(true).create(true).truncate(true).open(log_file_path).expect("Cannot open log file");

    while let Ok(packet) = cap.next_packet() {
        total_packets += 1;
        let ethernet = EthernetPacket::new(packet.data).unwrap();
        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    let packet_info = PacketInfo {
                        src_ip: ipv4.get_source().to_string(),
                        dst_ip: ipv4.get_destination().to_string(),
                        src_port: tcp.get_source(),
                        dst_port: tcp.get_destination(),
                        tcp_flags: tcp.get_flags(),
                    };
                    execute_query(&query, packet_info, threshold, &mut sketch, &mut ground_truth);
                }
            }
        }

        if current_epoch_start.elapsed() >= Duration::from_secs(epoch_size) {
            println!("\n========================= EPOCH RESULTS =========================");
            let mut log_output = String::new();
            let mut packet_count = total_packets;
            total_packets = 0;
            let mut epoch_total_are = 0.0;
            let mut epoch_valid_entries = 0;

            for (d_ip, true_count) in &ground_truth {
                if *true_count > threshold {
                    let estimated_count = sketch.estimate(d_ip);
                    let re = ((estimated_count as f64 - *true_count as f64).abs()) / (*true_count as f64);
                    epoch_total_are += re;
                    epoch_valid_entries += 1;

                    let output = format!("New TCP connections detected: {} -> True: {}, Estimated: {}, RE: {:.4}", d_ip, true_count, estimated_count, re);
                    println!("{}", output);
                    log_output.push_str(&format!("{}\n", output));
                }
            }

            let avg_are = if epoch_valid_entries > 0 {
                epoch_total_are / epoch_valid_entries as f64
            } else {
                0.0
            };
            let are_output = format!("Average ARE for epoch: {:.4}", avg_are);
            let packet_output = format!("Total packets processed in epoch: {}", packet_count);
            let valid_entries_output = format!("Valid entries counted: {}", epoch_valid_entries);
            println!("{}", are_output);
            println!("{}", packet_output);
            println!("{}", valid_entries_output);
            log_output.push_str(&format!("{}\n{}\n{}\n", are_output, packet_output, valid_entries_output));

            sketch.clear();
            ground_truth.clear();
            log_file.write_all(log_output.as_bytes()).expect("Failed to write to log file");
            current_epoch_start = Instant::now();
        }
    }
}