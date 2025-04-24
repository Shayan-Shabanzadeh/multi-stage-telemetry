use crate::query_plan::{QueryPlan, Operation, Field, ReduceType};

/// Query 1: TCP New Connection
pub fn query_1() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::TcpFlag, "2".to_string())]),
            Operation::Map("(dst_ip, count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                // reduce_type: ReduceType::DeterministicReduce,
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 172032, depth: 3, seed: 42 },
                // reduce_type: ReduceType::FCMReduce { depth: 2, width_l1: 65536, width_l2: 8192, width_l3: 1024, threshold_l1: 254, threshold_l2: 65534, seed: 42 },
                // reduce_type: ReduceType::ElasticReduce { depth: 4, width: 516096, seed: 42 },
                field_name: "count".to_string(),
            },
            Operation::FilterResult { threshold: 40 , field_name: "count".to_string() },
        ],
    }
}

// Query 2: SSH Brute
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
                // reduce_type: ReduceType::CMReduce { memory_in_bytes: 524288, depth: 3, seed: 42 },
                reduce_type: ReduceType::FCMReduce { depth: 2, width_l1: 524288, width_l2: 65536, width_l3: 8192, threshold_l1: 254, threshold_l2: 65534, seed: 42 },
                // reduce_type: ReduceType::ElasticReduce { depth: 4, width: 1024, seed: 42 },
                field_name: "count".to_string(),
            },
            Operation::FilterResult { threshold: 40  , field_name: "count".to_string() },
            // Operation::Map("(p.dst_ip)".to_string()),
        ],
    }
}

// Query 3: SuperSpreader	
pub fn query_3() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Map("(dst_ip, src_ip)".to_string()),
            Operation::Distinct {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string()],
                // distinct_type: ReduceType::DeterministicReduce,
                // 50 KB
                distinct_type: ReduceType::BloomFilter { size: 400000,num_hashes: 5, seed: 42,},
            },
            Operation::Map("(src_ip, count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                // reduce_type: ReduceType::DeterministicReduce,
                //  84 KB
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 86016, depth: 3, seed: 42 },
                // reduce_type: ReduceType::FCMReduce { depth: 2, width_l1: 32768, width_l2: 4096, width_l3: 512, threshold_l1: 254, threshold_l2: 65534, seed: 42 },
                // reduce_type: ReduceType::ElasticReduce { depth: 4, width: 1024, seed: 42 },
                field_name: "count".to_string(),
            },
            Operation::FilterResult { threshold: 40  , field_name: "count".to_string() },
        ],
    }
}


// Query 4: Port Scan
pub fn query_4() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]), // Filter TCP packets
            Operation::Map("(src_ip, dst_port)".to_string()),
            Operation::Distinct {
                keys: vec!["src_ip".to_string(), "dst_port".to_string()],
                // distinct_type: ReduceType::DeterministicReduce,
                distinct_type: ReduceType::BloomFilter { size: 400000,num_hashes: 5, seed: 42,},
            },
            Operation::Map("(src_ip, dst_port , count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                // reduce_type: ReduceType::DeterministicReduce,
                // 50 KB
                // reduce_type: ReduceType::FCMReduce { depth: 2, width_l1: 19500, width_l2: 2438, width_l3: 304, threshold_l1: 254, threshold_l2: 65534, seed: 42 },
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 51184, depth: 3, seed: 42 },
                field_name: "count".to_string(),
            },
            Operation::FilterResult { threshold: 40  , field_name: "count".to_string() },
        ],
    }
}

// Query 5: Detect heavy hitters
pub fn query_5() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Map ("(dst_ip, src_ip, total_len)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string()],
                // reduce_type: ReduceType::DeterministicReduce,
                // reduce_type: ReduceType::CMReduce { memory_in_bytes: 172032, depth: 3, seed: 42 },
                reduce_type: ReduceType::FCMReduce { depth: 2, width_l1: 65536, width_l2: 8192, width_l3: 1024, threshold_l1: 254, threshold_l2: 65534, seed: 42 },
                field_name: "total_len".to_string(),
            },
            Operation::FilterResult { threshold: 60000  , field_name: "total_len".to_string() },
        ],
    }
}




// Query 6: Detect SYN flood attacks
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
                threshold: 40,
                field_name: "count".to_string(),
            },
        ],
    };

    syn_flood_victim
}

// Completed Flow	
pub fn query_7() -> QueryPlan {
    let n_syn = QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]),
            Operation::Filter(vec![(Field::TcpFlag, "2".to_string())]),
            Operation::Map("(dst_ip, left_count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                reduce_type: ReduceType::DeterministicReduce,
                field_name: "left_count".to_string(),
            },
        ],
    };

    // Query to count FIN packets (TCP flags = 1)
    let n_fin = QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]),
            Operation::Filter(vec![(Field::TcpFlag, "1".to_string())]),
            Operation::Map("(src_ip, right_count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                reduce_type: ReduceType::DeterministicReduce,
                field_name: "right_count".to_string(),
            },
        ],
    };

    // Join the results of n_syn and n_fin
    let q3 = QueryPlan {
        operations: vec![
            // Join n_syn and n_fin
            Operation::Join {
                left_query: Box::new(n_syn),
                right_query: Box::new(n_fin),
                left_keys: vec!["dst_ip".to_string()],
                right_keys: vec!["src_ip".to_string()],
            },
            // Map the joined results and calculate the difference
            Operation::Map("(dst_ip, src_ip, diff = count1 - count2)".to_string()),
            // Filter where the difference >= T (T = 1)
            Operation::FilterResult {
                threshold: 1,
                field_name: "diff".to_string(),
            },
            // Map only the destination IP
            Operation::Map("(dst_ip)".to_string()),
        ],
    };

    q3
}


// Query 8: Detect Slowloris attacks
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