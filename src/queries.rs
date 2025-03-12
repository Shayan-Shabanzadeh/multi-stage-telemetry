use crate::query_plan::{QueryPlan, Operation, Field, ReduceType};

/// Query 1: Detect TCP SYN flood attacks
/// Hosts for which the number of newly opened TCP connections exceeds threshold.
pub fn query_1() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::TcpFlag, "2".to_string())]),
            Operation::Map("(p.dst_ip, count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                function: "sum".to_string(),
                reduce_type: ReduceType::DeterministicReduce,
                // reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
                // reduce_type: ReduceType::FCMReduce { depth: 4, width: 1024, seed: 42 },
                // reduce_type: ReduceType::ElasticReduce { depth: 4, width: 1024, seed: 42 },
                index: 8,

            },
            Operation::FilterResult { threshold: 40 , index: 8 },
        ],
    }
}

/// Query 2: Detect brute-force SSH attacks
/// Hosts that receive similar-sized packets from more than threshold unique senders.
pub fn query_2() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Map("(p.dst_ip, p.src_ip, p.total_len)".to_string()),
            Operation::Distinct {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string(), "total_len".to_string()],
                distinct_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
            },
            // Operation::Map("(p.dst_ip, p.total_len)".to_string()),
            Operation::Map("(p.dst_ip, p.total_len, count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string(), "total_len".to_string()],
                function: "sum".to_string(),
                reduce_type: ReduceType::DeterministicReduce,
                // reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
                // reduce_type: ReduceType::FCMReduce { depth: 4, width: 1024, seed: 42 },
                // reduce_type: ReduceType::ElasticReduce { depth: 4, width: 1024, seed: 42 },
                index: 5,
            },
            Operation::FilterResult { threshold: 40000000  , index: 5 },
            // Operation::Map("(p.dst_ip)".to_string()),
        ],
    }
}

/// Query 3: Super spreader detection
/// Detects hosts that make too many connections to different destinations.
pub fn query_3() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Map("(p.dst_ip, p.src_ip)".to_string()),
            Operation::Distinct {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string()],
                distinct_type: ReduceType::DeterministicReduce,
                // distinct_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
                // distinct_type: ReduceType::FCMReduce { depth: 4, width: 1024, seed: 42 },
                // distinct_type: ReduceType::ElasticReduce { depth: 4, width: 1024, seed: 42 },
            },
            Operation::Map("(p.src_ip, count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                function: "sum".to_string(),
                reduce_type: ReduceType::DeterministicReduce,
                // reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
                // reduce_type: ReduceType::FCMReduce { depth: 4, width: 1024, seed: 42 },
                // reduce_type: ReduceType::ElasticReduce { depth: 4, width: 1024, seed: 42 },
                index: 8,
            },
            Operation::FilterResult { threshold: 100  , index: 8 },
            // Operation::Map("(p.src_ip)".to_string()),
        ],
    }
}


/// Query 4: Detect port scan attacks
/// One host is scanning a lot of different ports, potentially before an attack.
pub fn query_4() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]), // Filter TCP packets
            // TODO uncomment 
            // Operation::Map("(p.src_ip, p.dst_port)".to_string()),
            Operation::Distinct {
                keys: vec!["src_ip".to_string(), "dst_port".to_string()],
                distinct_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
            },
            Operation::Map("(p.src_ip, p.dst_port , count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                function: "sum".to_string(),
                // reduce_type: ReduceType::FCMReduce { depth: 4, width: 1024, seed: 42 },
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
                index: 8,
            },
            Operation::FilterResult { threshold: 1000 , index: 8 },
        ],
    }
}

/// Query 5: Detect heavy hitters
/// Hosts that send a large amount of data to specific destinations.
pub fn query_5() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Map("(p.dst_ip, p.src_ip, count = p.total_len)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string()],
                function: "sum".to_string(),
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
                index: 8,
            },
            Operation::FilterResult { threshold: 1000 , index: 8 },
            Operation::Map("(p.dst_ip)".to_string()),
        ],
    }
}


/// Query 8: Detect Slowloris attacks
/// Hosts for which the average number of connections per byte exceeds a threshold.
pub fn query_8_1() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]), // Filter TCP packets
            Operation::Map("(p.dst_ip, count = p.total_len)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                function: "sum".to_string(),
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
                index: 8,
            },
            Operation::FilterResult { threshold: 500 , index: 8 },
        ],
    }
}


/// Query 8: Detect Slowloris attacks
/// Hosts for which the average number of connections per byte exceeds a threshold.
pub fn query_8() -> QueryPlan {
    let n_conns = QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]), // Filter TCP packets
            Operation::Map("(p.dst_ip, p.src_ip, p.src_port)".to_string()),
            Operation::Distinct {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string(), "src_port".to_string()],
                distinct_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
            },
            Operation::Map("(p.dst_ip, count = 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                function: "sum".to_string(),
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
                index: 8,
            },
            Operation::FilterResult { threshold: 5 , index: 8 },
        ],
    };

    let n_bytes = QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "6".to_string())]), // Filter TCP packets
            Operation::Map("(p.dst_ip, count = p.total_len)".to_string()),
            Operation::Reduce { 
                keys: vec!["dst_ip".to_string()],
                function: "sum".to_string(),
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
                index: 8,
            },
            Operation::FilterResult { threshold: 500 ,index: 8 },
        ],
    };


    // let n_bytes_2 = QueryPlan {
    //     operations: vec![
    //         Operation::Filter(vec![(Field::Protocol, "6".to_string())]), // Filter TCP packets
    //         Operation::Map("(p.dst_ip, count = p.total_len)".to_string()),
    //         Operation::Reduce { 
    //             keys: vec!["dst_ip".to_string()],
    //             function: "sum".to_string(),
    //             reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
    //             index: 8,
    //         },
    //         Operation::FilterResult { threshold: 1000 ,index: 8 },
    //     ],
    // };

    QueryPlan {
        operations: vec![
            Operation::Join {
                left_query: Box::new(n_bytes),
                right_query: Box::new(n_conns),


                // left_query: Box::new(n_conns),
                // right_query: Box::new(n_bytes),


                // left_query: Box::new(n_bytes),
                // right_query: Box::new(n_bytes_2),
                join_keys: vec!["dst_ip".to_string()],
            },
            Operation::Map("(p.dst_ip, count1 / count2)".to_string()),
            Operation::FilterResult { threshold: 90  , index: 10},
            Operation::Map("(p.dst_ip)".to_string()),
        ],
    }
}

//  Query 11: Detect DNS reflection attacks
//  Hosts that receive a large number of DNS responses from specific sources.
pub fn query_11() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::Protocol, "17".to_string())]), // Filter UDP packets
            Operation::Filter(vec![(Field::SourcePort, "53".to_string())]), // Filter DNS responses
            Operation::Filter(vec![(Field::DnsNsType, "46".to_string())]), // Filter specific DNS type
            Operation::Map("(p.dst_ip, p.src_ip)".to_string()),
            Operation::Distinct {
                keys: vec!["dst_ip".to_string(), "src_ip".to_string(), "total_len".to_string()],
                distinct_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
            },
            Operation::Map("(p.dst_ip, 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                function: "sum".to_string(),
                reduce_type: ReduceType::CMReduce { memory_in_bytes: 4096, depth: 4, seed: 42 },
                index: 7,
            },
            Operation::FilterResult { threshold: 1000 ,index: 8  },
            Operation::Map("(p.dst_ip)".to_string()),
        ],
    }
}