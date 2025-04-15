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
        reduce_type: ReduceType,
        field_name: String,
    },
    FilterResult { threshold: u64, field_name: String },
    Distinct {
        keys: Vec<String>,
        distinct_type: ReduceType,
    },
    Join {
        left_query: Box<QueryPlan>,
        right_query: Box<QueryPlan>,
        left_keys: Vec<String>,
        right_keys: Vec<String>, 
    },
    MapJoin(String),
    FilterJoin { threshold: u16, field_name: String },
}

pub enum ReduceType {
    CMReduce { memory_in_bytes: usize, depth: usize, seed: u64 },
    FCMReduce {
        depth: usize,
        width_l1: usize,
        width_l2: usize,
        width_l3: usize,
        threshold_l1: u32,
        threshold_l2: u32,
        seed: u64,
    },
    ElasticReduce { depth: usize, width: usize, seed: u64 },
    DeterministicReduce,
    BloomFilter {size: usize, num_hashes: usize, seed: u64},
}

pub struct QueryPlan {
    pub operations: Vec<Operation>,
}