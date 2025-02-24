mod count_min_sketch;
mod pcap_processor;
mod query_parser;
mod query_plan;
mod packet_info;

use std::env;
use pcap_processor::process_pcap;
use query_parser::parse_query;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: {} <pcap_file> <epoch_size_seconds> <threshold>", args[0]);
        return;
    }

    let pcap_file = &args[1];
    let epoch_size: u64 = args[2].parse().expect("Invalid epoch size");
    let threshold: usize = args[3].parse().expect("Invalid threshold");

    let query = parse_query();
    process_pcap(pcap_file, epoch_size, threshold, query);
}