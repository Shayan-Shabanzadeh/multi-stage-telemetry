use crate::packet_info::PacketInfo;
use crate::count_min_sketch::CountMinSketch;
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct QueryPlan {
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
    Filter(Vec<(Field, String)>),
    Map(String),
    Reduce { keys: Vec<String>, function: String },
    FilterResult(String),
}

pub fn execute_query(query: &QueryPlan, packet: PacketInfo, threshold: usize, sketch: &mut CountMinSketch, ground_truth: &mut BTreeMap<String, usize>) {
    let mut current_packet = Some(packet);

    for op in &query.operations {
        match op {
            Operation::Filter(conditions) => {
                if let Some(ref p) = current_packet {
                    let pass = conditions.iter().all(|(field, value)| match field {
                        Field::SourceIp => &p.src_ip == value,
                        Field::DestIp => &p.dst_ip == value,
                        Field::SourcePort => p.src_port.to_string() == *value,
                        Field::DestPort => p.dst_port.to_string() == *value,
                        Field::TcpFlag => p.tcp_flags.to_string() == *value,
                    });

                    if !pass {
                        current_packet = None;
                        break;
                    }
                }
            }
            Operation::Map(_) => {
                // Map operations are simplified here; pass the packet along.
            }
            Operation::Reduce { keys: _, function: _ } => {
                if let Some(ref p) = current_packet {
                    let combined_key = format!("{}-{}", p.dst_ip, p.src_ip);
                    sketch.increment(&combined_key, 1);
                    *ground_truth.entry(combined_key).or_insert(0) += 1;
                }
            }
            Operation::FilterResult(_) => {
                if let Some(ref p) = current_packet {
                    let combined_key = format!("{}-{}", p.dst_ip, p.src_ip);
                    if sketch.estimate(&combined_key) < threshold as u64 {
                        current_packet = None;
                    }
                }
            }
        }
    }
}
