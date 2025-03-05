pub enum Field {
    SourceIp,
    DestIp,
    SourcePort,
    DestPort,
    TcpFlag,
    Protocol,
}

pub enum ReduceType {
    CMReduce { memory_in_bytes: usize, depth: usize, seed: u64 },
    FCMReduce { depth: usize, width: usize, seed: u64 },
    ElasticReduce { depth: usize, width: usize, seed: u64 },
    // Add other reduce types here in the future
}

pub enum Operation {
    Filter(Vec<(Field, String)>),
    Map(String),
    Reduce {
        keys: Vec<String>,
        function: String,
        reduce_type: ReduceType,
    },
    FilterResult(String),
    Distinct(Vec<String>),
}

pub struct QueryPlan {
    pub operations: Vec<Operation>,
}