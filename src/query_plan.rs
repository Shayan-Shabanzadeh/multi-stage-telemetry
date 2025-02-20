#[derive(Debug)]
pub struct QueryPlan {
    pub window: u64,
    pub operations: Vec<Operation>,
}

#[derive(Debug)]
pub enum Operation {
    Filter(String), // Expression as string (e.g., "p.tcp.flags == 2")
    Map(String),    // Mapping expression (e.g., "(p.dst_ip, 1)")
    Reduce { keys: Vec<String>, function: String }, // Reduce with keys and function
    FilterResult(String), // Post-reduce filter (e.g., "count > Th")
}