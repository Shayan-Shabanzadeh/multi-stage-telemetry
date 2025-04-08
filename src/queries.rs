use crate::query_plan::{QueryPlan, Operation, Field, ReduceType};

/// Query 1: Detect TCP SYN flood attacks
/// Hosts for which the number of newly opened TCP connections exceeds threshold.
pub fn query_1() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::TcpFlag, "2".to_string())]),
            Operation::Map("(dst_ip, count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                // reduce_type: ReduceType::DeterministicReduce,
                // reduce_type: ReduceType::CMReduce { memory_in_bytes: 524288, depth: 3, seed: 42 },
                // 1572864 bytes = 1.5 MB
                // 524288 bytes = 512 KB
                // 65536 bytes = 64 KB
                // 8192 bytes = 8 KB
                reduce_type: ReduceType::FCMReduce { depth: 2, width_l1: 524288, width_l2: 65536, width_l3: 8192, threshold_l1: 254, threshold_l2: 65534, seed: 42 },
                // reduce_type: ReduceType::ElasticReduce { depth: 4, width: 524288, seed: 42 },
                field_name: "count".to_string(),
            },
            Operation::FilterResult { threshold: 40 , field_name: "count".to_string() },
        ],
    }
}

// Query 2: Detect brute-force SSH attacks
// Hosts that receive similar-sized packets from more than threshold unique senders.
pub fn query_2() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Map("(dst_ip, src_ip, total_len)".to_string()),
            Operation::Distinct {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string() , "total_len".to_string()],
                distinct_type: ReduceType::DeterministicReduce,
                // distinct_type: ReduceType::BloomFilter {
                //     expected_items: 10000,
                //     false_positive_rate: 0.01, 
                // },
            },
            Operation::Map("(dst_ip, total_len, count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string(), "total_len".to_string()],
                // reduce_type: ReduceType::DeterministicReduce,
                // reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
                reduce_type: ReduceType::FCMReduce { depth: 2, width_l1: 524288, width_l2: 65536, width_l3: 8192, threshold_l1: 254, threshold_l2: 65534, seed: 42 },
                // reduce_type: ReduceType::ElasticReduce { depth: 4, width: 1024, seed: 42 },
                field_name: "count".to_string(),
            },
            Operation::FilterResult { threshold: 40  , field_name: "count".to_string() },
            // Operation::Map("(p.dst_ip)".to_string()),
        ],
    }
}

// Query 3: Super spreader detection
// Detects hosts that make too many connections to different destinations.
pub fn query_3() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Map("(dst_ip, src_ip)".to_string()),
            Operation::Distinct {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string()],
                distinct_type: ReduceType::DeterministicReduce,
                // distinct_type: ReduceType::BloomFilter {
                //     expected_items: 100000000,
                //     false_positive_rate: 0.01, 
                // },
            },
            Operation::Map("(src_ip, count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                reduce_type: ReduceType::DeterministicReduce,
                // reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
                // reduce_type: ReduceType::FCMReduce { depth: 4, width: 1024, seed: 42 },
                // reduce_type: ReduceType::ElasticReduce { depth: 4, width: 1024, seed: 42 },
                field_name: "count".to_string(),
            },
            Operation::FilterResult { threshold: 40  , field_name: "count".to_string() },
        ],
    }
}


// Query 4: Detect port scan attacks
// One host is scanning a lot of different ports, potentially before an attack.
pub fn query_4() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]), // Filter TCP packets
            Operation::Map("(src_ip, dst_port)".to_string()),
            Operation::Distinct {
                keys: vec!["src_ip".to_string(), "dst_port".to_string()],
                distinct_type: ReduceType::DeterministicReduce,
            },
            Operation::Map("(src_ip, dst_port , count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                // reduce_type: ReduceType::FCMReduce { depth: 4, width: 1024, seed: 42 },
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 3145728, depth: 3, seed: 42 },
                field_name: "count".to_string(),
            },
            Operation::FilterResult { threshold: 40  , field_name: "count".to_string() },
        ],
    }
}

// Query 5: Detect heavy hitters
// Hosts that send a large amount of data to specific destinations.
pub fn query_5() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Map ("(dst_ip, src_ip, total_len)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string()],
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 3145728, depth: 3, seed: 42 },
                field_name: "total_len".to_string(),
            },
            Operation::FilterResult { threshold: 40  , field_name: "total_len".to_string() },
        ],
    }
}


// Query 6: Detect SYN flood attacks
// Hosts for which the number of half-open TCP connections exceeds threshold Th.
pub fn query_6() -> QueryPlan {
    // Query to count SYN packets (TCP flags = 2)
    let n_syn = QueryPlan {
        operations: vec![
            Operation::Filter(vec![
                (Field::Protocol, "6".to_string()), // Filter TCP packets
                (Field::TcpFlag, "2".to_string()),  // Filter SYN packets
            ]),
            Operation::Map("(dst_ip, left_count = 1)".to_string()), // Map destination IP with count = 1
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()], // Group by destination IP
                reduce_type: ReduceType::CMReduce { 
                    memory_in_bytes: 3145728, 
                    depth: 3, 
                    seed: 42 
                },
                field_name: "left_count".to_string(), // Sum the counts
            },
        ],
    };

    // Query to count SYN-ACK packets (TCP flags = 17)
    let n_synack = QueryPlan {
        operations: vec![
            Operation::Filter(vec![
                (Field::Protocol, "6".to_string()), // Filter TCP packets
                (Field::TcpFlag, "17".to_string()), // Filter SYN-ACK packets
            ]),
            Operation::Map("(src_ip, right_count = 1)".to_string()), // Map source IP with count = 1
            Operation::Reduce {
                keys: vec!["src_ip".to_string()], // Group by source IP
                reduce_type: ReduceType::CMReduce { 
                    memory_in_bytes: 3145728, 
                    depth: 3, 
                    seed: 42 
                },
                field_name: "right_count".to_string(), // Sum the counts
            },
        ],
    };

    // Join n_syn and n_synack queries
    let syn_flood_victim = QueryPlan {
        operations: vec![
            Operation::Join {
                left_query: Box::new(n_syn),
                right_query: Box::new(n_synack),
                left_keys: vec!["dst_ip".to_string()], 
                right_keys: vec!["src_ip".to_string()], 
            },
            Operation::MapJoin("(dst_ip, count = left_count + right_count)".to_string()),
            Operation::FilterResult { 
                threshold: 50,
                field_name: "count".to_string(),
            },
        ],
    };

    syn_flood_victim
}

// Query 8: Detect Slowloris attacks
// Hosts for which the average number of connections per byte exceeds a threshold.
pub fn query_8() -> QueryPlan {
    let n_conns = QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]),
            Operation::Map("(dst_ip, src_ip, src_port)".to_string()),
            Operation::Distinct {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string(), "src_port".to_string()],
                distinct_type: ReduceType::DeterministicReduce,
            },
            Operation::Map("(dst_ip, count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 3145728, depth: 3, seed: 42 },
                field_name: "count".to_string(),
            },
            Operation::FilterResult { threshold: 5  , field_name: "count".to_string() },
        ],
    };

    let n_bytes = QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]),
            Operation::Map("(dst_ip, total_len)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 3145728, depth: 3, seed: 42 },
                field_name: "total_len".to_string(),
            },
            Operation::FilterResult { threshold: 500  , field_name: "total_len".to_string() },
        ],
    };

    QueryPlan {
        operations: vec![
            Operation::Join {
                left_query: Box::new(n_bytes),
                right_query: Box::new(n_conns),
                left_keys: vec!["dst_ip".to_string()],
                right_keys: vec!["dst_ip".to_string()], 
            },
            // Operation::Map("(p.dst_ip, count = count1 / count2)".to_string()),
            // Operation::FilterResult { threshold: 90  , field_name: "count".to_string() },
        ],
    }
}

//  Query 11: Detect DNS reflection attacks
//  Hosts that receive a large number of DNS responses from specific sources.
// pub fn query_11() -> QueryPlan {
//     QueryPlan {
//         operations: vec![
//             Operation::Filter(vec![(Field::Protocol, "17".to_string())]), // Filter UDP packets
//             Operation::Filter(vec![(Field::SourcePort, "53".to_string())]), // Filter DNS responses
//             Operation::Filter(vec![(Field::DnsNsType, "46".to_string())]), // Filter specific DNS type
//             Operation::Map("(p.dst_ip, p.src_ip)".to_string()),
//             Operation::Distinct {
//                 keys: vec!["dst_ip".to_string(), "src_ip".to_string(), "total_len".to_string()],
//                 distinct_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
//             },
//             Operation::Map("(p.dst_ip, 1)".to_string()),
//             Operation::Reduce {
//                 keys: vec!["dst_ip".to_string()],
//                 function: "sum".to_string(),
//                 reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
//                 index: 7,
//             },
//             Operation::FilterResult { threshold: 1000 ,index: 8  },
//             Operation::Map("(p.dst_ip)".to_string()),
//         ],
//     }
// }