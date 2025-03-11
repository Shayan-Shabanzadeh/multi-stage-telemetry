pub enum Field {
    SourceIp,
    DestIp,
    SourcePort,
    DestPort,
    TcpFlag,
    Protocol,
    DnsNsType,
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

pub enum ReduceType {
    CMReduce { memory_in_bytes: usize, depth: usize, seed: u64 },
    FCMReduce { depth: usize, width: usize, seed: u64 },
    ElasticReduce { depth: usize, width: usize, seed: u64 },
}

pub struct QueryPlan {
    pub operations: Vec<Operation>,
}