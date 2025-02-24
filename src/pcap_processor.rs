use pcap::Capture;
use pnet::packet::{Packet, ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, udp::UdpPacket};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use crate::count_min_sketch::CountMinSketch;
use crate::query_plan::QueryPlan;
use crate::packet_info::PacketInfo;
use crate::query_plan::execute_query;

pub fn process_pcap(file_path: &str, epoch_size: u64, threshold: usize, query: QueryPlan) {
    let mut cap = Capture::from_file(file_path).expect("Failed to open PCAP file");
    let mut sketch = CountMinSketch::new(1024, 600);
    let mut ground_truth: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_packets = 0;

    let log_file_path = "telemetry_log.txt";
    let mut log_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(log_file_path)
        .expect("Cannot open log file");

    let mut current_epoch_start: Option<u64> = None;
    let mut first_packet_timestamp_in_epoch: Option<u64> = None;
    let mut last_packet_timestamp_in_epoch: Option<u64> = None;
    let mut packets_in_epoch: Vec<String> = Vec::new();

    while let Ok(packet) = cap.next_packet() {
        let packet_timestamp = packet.header.ts.tv_sec as u64;

        if current_epoch_start.is_none() {
            current_epoch_start = Some(packet_timestamp);
            first_packet_timestamp_in_epoch = Some(packet_timestamp);
        }

        if first_packet_timestamp_in_epoch.is_none() {
            first_packet_timestamp_in_epoch = Some(packet_timestamp);
        }

        last_packet_timestamp_in_epoch = Some(packet_timestamp);
        total_packets += 1;

        let ethernet = EthernetPacket::new(packet.data).unwrap();
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

                    // ✅ Commented out for cleaner output; uncomment below line to enable packet-level printing.
                    // println!("{}", packet_log);

                    packets_in_epoch.push(packet_log);

                    execute_query(&query, packet_info, threshold, &mut sketch, &mut ground_truth);
                }
            }
        }

        if packet_timestamp - current_epoch_start.unwrap() >= epoch_size {
            println!("\n========================= EPOCH RESULTS =========================");
            println!("Epoch start timestamp: {}", first_packet_timestamp_in_epoch.unwrap());
            println!("Epoch end timestamp: {}", last_packet_timestamp_in_epoch.unwrap());

            let mut log_output = String::new();
            let packet_count = total_packets;
            total_packets = 0;
            let mut epoch_total_are = 0.0;
            let mut epoch_valid_entries = 0;

            println!("Packets processed in this epoch:");
            for packet_log in &packets_in_epoch {
                log_output.push_str(&format!("{}\n", packet_log));
            }

            for (combined_key, true_count) in &ground_truth {
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

            let are_output = format!("Average ARE for epoch: {:.4}", avg_are);
            let packet_output = format!("Total packets processed in epoch: {}", packet_count);
            let valid_entries_output = format!("Valid entries counted: {}", epoch_valid_entries);

            println!("{}", are_output);
            println!("{}", packet_output);
            println!("{}", valid_entries_output);

            log_output.push_str(&format!(
                "{}\n{}\n{}\nEpoch start timestamp: {}\nEpoch end timestamp: {}\n",
                are_output,
                packet_output,
                valid_entries_output,
                first_packet_timestamp_in_epoch.unwrap(),
                last_packet_timestamp_in_epoch.unwrap()
            ));

            sketch.clear();
            ground_truth.clear();
            packets_in_epoch.clear();

            log_file.write_all(log_output.as_bytes()).expect("Failed to write to log file");

            current_epoch_start = Some(current_epoch_start.unwrap() + epoch_size);
            first_packet_timestamp_in_epoch = None;
            last_packet_timestamp_in_epoch = None;
        }
    }

    if first_packet_timestamp_in_epoch.is_some() && last_packet_timestamp_in_epoch.is_some() {
        println!("\n========================= FINAL EPOCH RESULTS =========================");
        println!("Epoch start timestamp: {}", first_packet_timestamp_in_epoch.unwrap());
        println!("Epoch end timestamp: {}", last_packet_timestamp_in_epoch.unwrap());

        let mut log_output = String::new();
        let packet_count = total_packets;
        let mut epoch_total_are = 0.0;
        let mut epoch_valid_entries = 0;

        for packet_log in &packets_in_epoch {
            log_output.push_str(&format!("{}\n", packet_log));
        }

        for (combined_key, true_count) in &ground_truth {
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

        let are_output = format!("Average ARE for final epoch: {:.4}", avg_are);
        let packet_output = format!("Total packets processed in final epoch: {}", packet_count);
        let valid_entries_output = format!("Valid entries counted in final epoch: {}", epoch_valid_entries);

        println!("{}", are_output);
        println!("{}", packet_output);
        println!("{}", valid_entries_output);

        log_output.push_str(&format!(
            "{}\n{}\n{}\nEpoch start timestamp: {}\nEpoch end timestamp: {}\n",
            are_output,
            packet_output,
            valid_entries_output,
            first_packet_timestamp_in_epoch.unwrap(),
            last_packet_timestamp_in_epoch.unwrap()
        ));

        sketch.clear();
        ground_truth.clear();
        packets_in_epoch.clear();
        log_file.write_all(log_output.as_bytes()).expect("Failed to write to log file");
    }
}
