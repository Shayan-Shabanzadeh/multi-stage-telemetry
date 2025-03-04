pub enum Field {
    SourceIp,
    DestIp,
    SourcePort,
    DestPort,
    TcpFlag,
}

pub enum ReduceType {
    CountMinReduce { width: usize, depth: usize, seed: u64 },
    // Add other reduce types here in the future
}

pub enum Operation {
    Filter(Vec<(Field, String)>),
    Map(String),
    Reduce { keys: Vec<String>, function: String, reduce_type: ReduceType },
    FilterResult(String),
}

pub struct QueryPlan {
    pub operations: Vec<Operation>,
}