use crate::query_plan::{QueryPlan, Operation, Field, ReduceType};
use crate::config::{get_reduce_type_from_env, get_distinct_type_from_env, DistinctType};


/// Query 1: TCP New Connection
pub fn query_1() -> QueryPlan {
    let reduce_type = get_reduce_type_from_env();

    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::TcpFlag, "2".to_string())]),
            Operation::Map("(dst_ip, count = 1)".to_string()),
            // reduce_type: ReduceType::CMReduce { memory_in_bytes: 172032, depth: 3, seed: 42 },
            // reduce_type: ReduceType::FCMReduce { depth: 2, width_l1: 65536, width_l2: 8192, width_l3: 1024, threshold_l1: 254, threshold_l2: 65534, seed: 42 },
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                reduce_type,
                field_name: "count".to_string(),
            },
            Operation::FilterResult {
                threshold: 2,
                field_name: "count".to_string(),
            },
        ],
    }
}

// Query 2: SSH Brute
pub fn query_2() -> QueryPlan {
    let reduce_type = get_reduce_type_from_env();
    let distinct_type = get_distinct_type_from_env();
    // distinct_type: ReduceType::BloomFilter {
    //     expected_items: 10000,
    //     false_positive_rate: 0.01, 
    // },
    let distinct_op = match distinct_type {
        DistinctType::DeterministicReduce => ReduceType::DeterministicReduce,
        DistinctType::BloomFilter { size, num_hashes, seed } => {
            ReduceType::BloomFilter { size, num_hashes, seed }
        },
    };
    // reduce_type: ReduceType::CMReduce { memory_in_bytes: 524288, depth: 3, seed: 42 },
    // reduce_type: ReduceType::FCMReduce { depth: 2, width_l1: 524288, width_l2: 65536, width_l3: 8192, threshold_l1: 254, threshold_l2: 65534, seed: 42 },
    // reduce_type: ReduceType::ElasticReduce { depth: 4, width: 1024, seed: 42 },

    QueryPlan {
        operations: vec![
            Operation::Map("(dst_ip, src_ip, total_len)".to_string()),
            Operation::Distinct {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string(), "total_len".to_string()],
                distinct_type: distinct_op,
            },
            Operation::Map("(dst_ip, total_len, count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string(), "total_len".to_string()],
                reduce_type,
                field_name: "count".to_string(),
            },
            Operation::FilterResult {
                threshold: 40,
                field_name: "count".to_string(),
            },
        ],
    }
}



// Query 3: SuperSpreader
pub fn query_3() -> QueryPlan {
    let reduce_type = get_reduce_type_from_env();
    let distinct_type = get_distinct_type_from_env();

    let distinct_op = match distinct_type {
        DistinctType::DeterministicReduce => ReduceType::DeterministicReduce,
        DistinctType::BloomFilter { size, num_hashes, seed } => {
            ReduceType::BloomFilter { size, num_hashes, seed }
        },
    };

    QueryPlan {
        operations: vec![
            Operation::Map("(dst_ip, src_ip)".to_string()),
            Operation::Distinct {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string()],
                distinct_type: distinct_op,
            },
            Operation::Map("(src_ip, count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                reduce_type,
                field_name: "count".to_string(),
            },
            Operation::FilterResult {
                threshold: 40,
                field_name: "count".to_string(),
            },
        ],
    }
}	



// Query 4: Port Scan
pub fn query_4() -> QueryPlan {
    let reduce_type = get_reduce_type_from_env();
    let distinct_type = get_distinct_type_from_env();

    let distinct_op = match distinct_type {
        DistinctType::DeterministicReduce => ReduceType::DeterministicReduce,
        DistinctType::BloomFilter { size, num_hashes, seed } => {
            ReduceType::BloomFilter { size, num_hashes, seed }
        },
    };

    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]), // Filter TCP packets
            Operation::Map("(src_ip, dst_port)".to_string()),
            Operation::Distinct {
                keys: vec!["src_ip".to_string(), "dst_port".to_string()],
                distinct_type: distinct_op,
            },
            Operation::Map("(src_ip, dst_port , count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                reduce_type,
                field_name: "count".to_string(),
            },
            Operation::FilterResult {
                threshold: 40,
                field_name: "count".to_string(),
            },
        ],
    }
}

// Query 5: Detect heavy hitters
pub fn query_5() -> QueryPlan {
    let reduce_type = get_reduce_type_from_env();

    QueryPlan {
        operations: vec![
            Operation::Map("(dst_ip, src_ip, total_len)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string()],
                reduce_type,
                field_name: "total_len".to_string(),
            },
            Operation::FilterResult {
                threshold: 1,
                field_name: "total_len".to_string(),
            },
        ],
    }
}




// Query 6: Detect SYN flood attacks
pub fn query_6() -> QueryPlan {
    let reduce_type = get_reduce_type_from_env();

    // Query to count SYN packets (TCP flags = 2)
    let n_syn = QueryPlan {
        operations: vec![
            Operation::Filter(vec![
                (Field::Protocol, "6".to_string()),
                (Field::TcpFlag, "2".to_string()),
            ]),
            Operation::Map("(dst_ip, left_count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                reduce_type: reduce_type.clone(),
                field_name: "left_count".to_string(),
            },
        ],
    };

    // Query to count SYN-ACK packets (TCP flags = 17)
    let n_synack = QueryPlan {
        operations: vec![
            Operation::Filter(vec![
                (Field::Protocol, "6".to_string()),
                (Field::TcpFlag, "17".to_string()),
            ]),
            Operation::Map("(src_ip, right_count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                reduce_type,
                field_name: "right_count".to_string(),
            },
        ],
    };

    // Join n_syn and n_synack queries
    QueryPlan {
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
    }
}

// Completed Flow	
pub fn query_7() -> QueryPlan {
    let reduce_type = get_reduce_type_from_env();

    let n_syn = QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]),
            Operation::Filter(vec![(Field::TcpFlag, "2".to_string())]),
            Operation::Map("(dst_ip, left_count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                reduce_type: reduce_type.clone(),
                field_name: "left_count".to_string(),
            },
        ],
    };

    let n_fin = QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]),
            Operation::Filter(vec![(Field::TcpFlag, "1".to_string())]),
            Operation::Map("(src_ip, right_count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                reduce_type,
                field_name: "right_count".to_string(),
            },
        ],
    };

    QueryPlan {
        operations: vec![
            Operation::Join {
                left_query: Box::new(n_syn),
                right_query: Box::new(n_fin),
                left_keys: vec!["dst_ip".to_string()],
                right_keys: vec!["src_ip".to_string()],
            },
            Operation::Map("(dst_ip, src_ip, diff = count1 - count2)".to_string()),
            Operation::FilterResult {
                threshold: 1,
                field_name: "diff".to_string(),
            },
            Operation::Map("(dst_ip)".to_string()),
        ],
    }
}


// Query 8: Detect Slowloris attacks
pub fn query_8() -> QueryPlan {
    let reduce_type = get_reduce_type_from_env();
    let distinct_type = get_distinct_type_from_env();

    let distinct_op = match distinct_type {
        DistinctType::DeterministicReduce => ReduceType::DeterministicReduce,
        DistinctType::BloomFilter { size, num_hashes, seed } => {
            ReduceType::BloomFilter { size, num_hashes, seed }
        },
    };

    let n_conns = QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]),
            Operation::Map("(dst_ip, src_ip, src_port)".to_string()),
            Operation::Distinct {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string(), "src_port".to_string()],
                distinct_type: distinct_op,
            },
            Operation::Map("(dst_ip, count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                reduce_type: reduce_type.clone(),
                field_name: "count".to_string(),
            },
            Operation::FilterResult {
                threshold: 5,
                field_name: "count".to_string(),
            },
        ],
    };

    let n_bytes = QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]),
            Operation::Map("(dst_ip, total_len)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                reduce_type,
                field_name: "total_len".to_string(),
            },
            Operation::FilterResult {
                threshold: 500,
                field_name: "total_len".to_string(),
            },
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
        ],
    }
}
