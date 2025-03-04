use crate::query_plan::{QueryPlan, Operation, Field, ReduceType};

/// Query 1: Detect TCP SYN flood attacks
/// Hosts for which the number of newly opened TCP connections exceeds threshold.
pub fn query_1() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::TcpFlag, "2".to_string())]),
            Operation::Map("(p.src_ip, 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                function: "count".to_string(),
                // reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
                reduce_type: ReduceType::FCMReduce { depth: 4, width: 1024, seed: 42 },

            },
            Operation::FilterResult("count > Th".to_string()),
        ],
    }
}

/// Query 2: Detect brute-force SSH attacks
/// Hosts that receive similar-sized packets from more than threshold unique senders.
pub fn query_2() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Map("(p.dst_ip, p.src_ip, p.total_len)".to_string()),
            Operation::Distinct(vec!["dst_ip".to_string(), "src_ip".to_string(), "total_len".to_string()]),
            Operation::Map("(p.dst_ip, p.total_len)".to_string()),
            Operation::Map("(p.dst_ip, p.total_len, 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string(), "total_len".to_string()],
                function: "sum".to_string(),
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
            },
            Operation::FilterResult("count >= 40".to_string()),
            Operation::Map("(p.dst_ip)".to_string()),
        ],
    }
}

/// Query 3: Super spreader detection
/// Detects hosts that make too many connections to different destinations.
pub fn query_3() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Map("(p.dst_ip, p.src_ip)".to_string()),
            Operation::Distinct(vec!["dst_ip".to_string(), "src_ip".to_string()]),
            Operation::Map("(p.src_ip, 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                function: "sum".to_string(),
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
            },
            Operation::FilterResult("count >= 40".to_string()),
            Operation::Map("(p.src_ip)".to_string()),
        ],
    }
}


/// Query 4: Detect port scan attacks
/// One host is scanning a lot of different ports, potentially before an attack.
pub fn query_4() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]), // Filter TCP packets
            Operation::Map("(p.src_ip, p.dst_port)".to_string()),
            Operation::Distinct(vec!["src_ip".to_string(), "dst_port".to_string()]),
            Operation::Map("(p.src_ip, 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                function: "sum".to_string(),
                // reduce_type: ReduceType::FCMReduce { depth: 4, width: 1024, seed: 42 },
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
            },
            Operation::FilterResult("count >= T".to_string()),
            Operation::Map("(p.src_ip)".to_string()),
        ],
    }
}


/// TODO Query 5: Detect DDoS attacks


