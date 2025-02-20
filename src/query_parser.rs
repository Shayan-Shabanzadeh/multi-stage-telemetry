use crate::query_plan::{QueryPlan, Operation};

pub fn parse_query() -> QueryPlan {
    QueryPlan {
        window: 10, // Example window size `W`
        operations: vec![
            Operation::Filter("p.tcp_flags == 2".to_string()),           // First filter
            Operation::Map("(p.dst_ip, 1)".to_string()),                 // Map operation
            Operation::Reduce { keys: vec!["dst_ip".to_string()], function: "sum".to_string() }, // Reduce
            Operation::FilterResult("count > Th".to_string()),           // Final filter
        ],
    }
}