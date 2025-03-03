use crate::query_plan::{QueryPlan, Operation, Field};

pub fn parse_query() -> QueryPlan {
    QueryPlan {
        selected_fields: vec![
            Field::SourceIp,
            Field::DestIp,
            Field::SourcePort,
            Field::DestPort,
            Field::TcpFlag,
        ],
        operations: vec![
            Operation::Filter(vec![(Field::SourcePort, "53".to_string())]),
            Operation::Map(vec![Field::SourceIp, Field::DestIp]),
            Operation::Reduce {
                keys: vec![Field::DestIp],
                function: "count".to_string(),
            },
            Operation::FilterResult("count > 10".to_string()),
        ],
    }
}