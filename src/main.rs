mod sketch;
mod query_plan;
mod query_executor;
mod queries;
mod pcap_processor;
mod cm_sketch;
mod fcm_sketch;
mod elastic_sketch;
mod deterministic_sketch;
mod bloom_filter;
pub mod bobhash32;

use std::env;
use pcap_processor::process_pcap;
// use queries::{query_1, query_2, query_3, query_4, query_5, query_8, query_8_1, query_11};
use queries::{query_1, query_2, query_3, query_4, query_5, query_6 ,query_8};


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!("Usage: {} <pcap_file> <epoch_size_seconds> <threshold> <query_id>", args[0]);
                return;
    }

    let pcap_file = &args[1];
    let epoch_size: u64 = args[2].parse().expect("Invalid epoch size");
    let threshold: usize = args[3].parse().expect("Invalid threshold");
    let query_id: u8 = args[4].parse().expect("Invalid query ID");

    let query = match query_id {
        1 => query_1(),
        2 => query_2(),
        3 => query_3(),
        4 => query_4(),
        5 => query_5(),
        8 => query_8(),
        6 => query_6(),
        // 81 => query_8_1(),
        // 11 => query_11(),
        _ => {
            eprintln!("Invalid query ID: {}", query_id);
            return;
        }
    };
    process_pcap(pcap_file, epoch_size, threshold,query);
}