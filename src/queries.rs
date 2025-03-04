use crate::query_plan::{QueryPlan, Operation, Field, ReduceType};

pub fn query_1() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::TcpFlag, "2".to_string())]),
            Operation::Map("(p.src_ip, 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                function: "count".to_string(),
                reduce_type: ReduceType::CountMinReduce { width: 1024, depth: 600, seed: 42 },
            },
            Operation::FilterResult("count > Th".to_string()),
        ],
    }
}

pub fn query_2() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::DestPort, "80".to_string())]),
            Operation::Map("(p.dst_ip, 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                function: "count".to_string(),
                reduce_type: ReduceType::CountMinReduce { width: 1024, depth: 600, seed: 42 },
            },
            Operation::FilterResult("count > Th".to_string()),
        ],
    }
}

pub fn query_3() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::SourcePort, "443".to_string())]),
            Operation::Map("(p.src_ip, 1)".to_string()),
            Operation::Reduce {
                keys: vec!["src_ip".to_string()],
                function: "count".to_string(),
                reduce_type: ReduceType::CountMinReduce { width: 1024, depth: 600, seed: 42 },
            },
            Operation::FilterResult("count > Th".to_string()),
        ],
    }
}

pub fn query_4() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::TcpFlag, "18".to_string())]),
            Operation::Map("(p.dst_ip, 1)".to_string()),
            Operation::Reduce {
                keys: vec!["dst_ip".to_string()],
                function: "count".to_string(),
                reduce_type: ReduceType::CountMinReduce { width: 1024, depth: 600, seed: 42 },
            },
            Operation::FilterResult("count > Th".to_string()),
        ],
    }
}