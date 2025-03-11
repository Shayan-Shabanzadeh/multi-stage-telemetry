mod sketch;
mod query_plan;
mod query_executor;
mod queries;
mod pcap_processor;
mod cm_sketch;
mod fcm_sketch;
mod elastic_sketch;
mod deterministic_sketch;

use std::env;
use pcap_processor::process_pcap;
use queries::{query_1, query_2, query_3, query_4, query_5, query_11};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: {} <pcap_file> <epoch_size_seconds> <query_id>", args[0]);
        return;
    }

    let pcap_file = &args[1];
    let epoch_size: u64 = args[2].parse().expect("Invalid epoch size");
    let query_id: u8 = args[3].parse().expect("Invalid query ID");

    let query = match query_id {
        1 => query_1(),
        2 => query_2(),
        3 => query_3(),
        4 => query_4(),
        5 => query_5(),
        11 => query_11(),
        _ => {
            eprintln!("Invalid query ID: {}", query_id);
            return;
        }
    };
    process_pcap(pcap_file, epoch_size, query);
}