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
        index: usize,
    },
    FilterResult { threshold: u64, index: usize },
    Distinct(Vec<String>),
    Join {
        left_query: Box<QueryPlan>,
        right_query: Box<QueryPlan>,
        join_keys: Vec<String>,
    },
}

pub enum ReduceType {
    CMReduce { memory_in_bytes: usize, depth: usize, seed: u64 },
    FCMReduce { depth: usize, width: usize, seed: u64 },
    ElasticReduce { depth: usize, width: usize, seed: u64 },
    DeterministicReduce,
}

pub struct QueryPlan {
    pub operations: Vec<Operation>,
}