use pcap::{Capture, Device};
use std::collections::HashMap;
use std::env;
use std::time::{Duration, Instant};
use pnet::packet::{Packet, ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket};
use std::fs::OpenOptions;
use std::io::Write;
use std::collections::BTreeMap;
use twox_hash::XxHash64;
use std::hash::Hasher;

#[derive(Debug)]
struct CountMinSketch {
    width: usize,
    depth: usize,
    table: Vec<Vec<u64>>,
    keys: HashMap<String, usize>,
}

impl CountMinSketch {
    fn new(width: usize, depth: usize) -> Self {
        Self {
            width,
            depth,
            table: vec![vec![0; width]; depth],
            keys: HashMap::new(),
        }
    }

    fn hash(&self, item: &str, i: u32) -> usize {
        let mut hasher = XxHash64::with_seed(i as u64);
        hasher.write(item.as_bytes());
        (hasher.finish() as usize) % self.width
    }

    fn increment(&mut self, item: &str, count: u64) {
        for i in 0..self.depth {
            let index = self.hash(item, i as u32);
            self.table[i][index] += count;
        }
        *self.keys.entry(item.to_string()).or_insert(0) += count as usize;
    }

    fn estimate(&self, item: &str) -> u64 {
        (0..self.depth)
            .map(|i| self.table[i][self.hash(item, i as u32)])
            .min()
            .unwrap_or(0)
    }

    fn clear(&mut self) {
        for row in &mut self.table {
            row.fill(0);
        }
        self.keys.clear();
    }
}

fn process_pcap(file_path: &str, epoch_size: u64, threshold: usize) {
    let mut cap = Capture::from_file(file_path).expect("Failed to open PCAP file");
    let mut current_epoch_start = Instant::now();
    let mut sketch = CountMinSketch::new(1024, 600);
    let mut ground_truth: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_packets = 0;

    let log_file_path = "telemetry_log.txt";
    let mut log_file = OpenOptions::new().write(true).create(true).truncate(true).open(log_file_path).expect("Cannot open log file");
    
    while let Ok(packet) = cap.next_packet() {
        total_packets += 1;
        let ethernet = EthernetPacket::new(packet.data).unwrap();
        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    if tcp.get_flags() == 2 {  // TCP SYN flag
                        let d_ip = ipv4.get_destination().to_string();
                        sketch.increment(&d_ip, 1);
                        *ground_truth.entry(d_ip.clone()).or_insert(0) += 1;
                    }
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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: {} <pcap_file> <epoch_size_seconds> <threshold>", args[0]);
        return;
    }

    let pcap_file = &args[1];
    let epoch_size: u64 = args[2].parse().expect("Invalid epoch size");
    let threshold: usize = args[3].parse().expect("Invalid threshold");

    process_pcap(pcap_file, epoch_size, threshold);
}
