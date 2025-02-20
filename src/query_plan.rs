#[derive(Debug)]
pub struct QueryPlan {
    pub window: u64,
    pub operations: Vec<Operation>,
}

#[derive(Debug)]
pub enum Field {
    SourceIp,
    DestIp,
    SourcePort,
    DestPort,
    TcpFlag,
}

#[derive(Debug)]
pub enum Operation {
    Filter(Vec<(Field, String)>), // Multiple conditions (e.g., [(TcpFlag, "2"), (DestIp, "124.0.0.1")])
    Map(String),                  // Mapping expression (e.g., "(p.dst_ip, 1)")
    Reduce { keys: Vec<String>, function: String }, // Reduce with keys and function
    FilterResult(String),         // Post-reduce filter (e.g., "count > Th")
}