// config.rs
use crate::query_plan::ReduceType;
use std::env;

#[derive(Debug, Clone)]
pub enum DistinctType {
    DeterministicReduce,
    BloomFilter {
        size: usize,
        num_hashes: usize,
        seed: u64,
    },
}

fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|s| s.parse::<T>().ok())
        .unwrap_or(default)
}

pub fn get_reduce_type_from_env() -> ReduceType {
    match env::var("REDUCE_TYPE").unwrap_or_else(|_| "deterministic".to_string()).as_str() {
        "cms" => ReduceType::CMReduce {
            memory_in_bytes: parse_env("CM_MEMORY", 524288),
            depth: parse_env("CM_DEPTH", 3),
            seed: parse_env("CM_SEED", 42),
        },
        "fcm" => ReduceType::FCMReduce {
            depth: parse_env("FCM_DEPTH", 2),
            width_l1: parse_env("FCM_WIDTH_L1", 524288),
            width_l2: parse_env("FCM_WIDTH_L2", 65536),
            width_l3: parse_env("FCM_WIDTH_L3", 8192),
            threshold_l1: parse_env("FCM_THRESHOLD_L1", 254),
            threshold_l2: parse_env("FCM_THRESHOLD_L2", 65534),
            seed: parse_env("FCM_SEED", 42),
        },
        "beaucoup" => ReduceType::BeauCoupReduce {
            num_rows: parse_env("BC_ROWS", 8),
            num_coupons: parse_env("BC_COUPONS", 32768),
            d: parse_env("BC_D", 3),
            max_coupons_per_packet: parse_env("BC_MAX", 2),
            seed: parse_env("BC_SEED", 42),
        },
        _ => ReduceType::DeterministicReduce,
    }
}

pub fn get_distinct_type_from_env() -> DistinctType {
    match env::var("DISTINCT_TYPE").unwrap_or_else(|_| "deterministic".to_string()).as_str() {
        "bloom" => DistinctType::BloomFilter {
            size: parse_env("BF_SIZE", 300000),
            num_hashes: parse_env("BF_HASHES", 5),
            seed: parse_env("BF_SEED", 42),
        },
        _ => DistinctType::DeterministicReduce,
    }
}