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
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
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

/// Query 4: Detect TCP FIN-ACK flood attacks
/// This query filters packets with TCP flag set to 18 (FIN-ACK),
pub fn query_4() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::TcpFlag, "18".to_string())]),
            Operation::Map("(p.dst_ip, 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                function: "count".to_string(),
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
            },
            Operation::FilterResult("count > Th".to_string()),
        ],
    }
}