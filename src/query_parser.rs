// query_parser.rs
use crate::query_plan::{QueryPlan, Operation, Field};

pub fn parse_query() -> QueryPlan {
    QueryPlan {
        operations: vec![
            Operation::Filter(vec![(Field::SourcePort, "53".to_string())]),
            Operation::Map("(p.dst_ip, p.src_ip)".to_string()),
            Operation::Reduce { keys: vec!["dst_ip".to_string()], function: "distinct_count".to_string() },
            Operation::FilterResult("count > Th".to_string()),
        ],
    }
}