#[derive(Debug, Clone)]
pub struct QueryPlan {
    pub selected_fields: Vec<Field>,
    pub operations: Vec<Operation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Field {
    SourceIp,
    DestIp,
    SourcePort,
    DestPort,
    TcpFlag,
}

#[derive(Debug, Clone)]
pub enum Operation {
    Filter(Vec<(Field, String)>),
    Map(Vec<Field>),
    Reduce { keys: Vec<Field>, function: String },
    FilterResult(String),
}