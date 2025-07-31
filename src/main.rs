mod sketch;
mod query_plan;
mod query_executor;
mod queries;
mod pcap_processor;
mod cm_sketch;
mod fcm_sketch;
mod elastic_sketch;
mod fcm_first_layer_sketch;
mod deterministic_sketch;
mod bloom_filter;
pub mod bobhash32;
pub mod beaucoup;
mod config;
use config::{get_reduce_type_from_env, get_distinct_type_from_env};

use std::env;
use pcap_processor::process_pcap;
// use queries::{query_1, query_2, query_3, query_4, query_5, query_8, query_8_1, query_11};
use queries::{query_1, query_2, query_3, query_4, query_5, query_6 ,query_8};


fn main() {
    dotenv::dotenv().ok();
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!("Usage: {} <pcap_file> <epoch_size_seconds> <threshold> <query_id>", args[0]);
                return;
    }

    let pcap_file = &args[1];
    let epoch_size: u64 = args[2].parse().expect("Invalid epoch size");
    let threshold: usize = args[3].parse().expect("Invalid threshold");
    let query_id: u8 = args[4].parse().expect("Invalid query ID");
    let reduce_type = get_reduce_type_from_env();
    let distinct_type = get_distinct_type_from_env();
    println!("Running Query {} with config:", query_id);
    println!("  REDUCE_TYPE: {:?}", reduce_type);
    println!("  DISTINCT_TYPE: {:?}", distinct_type);

    let query = match query_id {
        1 => query_1(),
        2 => query_2(),
        3 => query_3(),
        4 => query_4(),
        5 => query_5(),
        6 => query_6(),
        8 => query_8(),
        _ => {
            eprintln!("Invalid query ID: {}", query_id);
            return;
        }
    };
    process_pcap(pcap_file, epoch_size, threshold,query);
}