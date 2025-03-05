use crate::query_plan::{QueryPlan, Operation, Field, ReduceType};
use crate::packet_info::PacketInfo;
use crate::sketch::Sketch;
use std::collections::{HashMap, HashSet};

pub fn execute_query(query: &QueryPlan, packet: PacketInfo, threshold: usize, sketches: &mut HashMap<String, Sketch>, ground_truth: &mut HashMap<String, u64>) {
    let mut current_packet = Some(packet);
    let mut seen = HashSet::new();

    for op in &query.operations {
        match op {
            Operation::Filter(conditions) => {
                if let Some(ref p) = current_packet {
                    let mut pass = true;
                    for (field, value) in conditions {
                        pass &= match field {
                            Field::SourceIp => &p.src_ip == value,
                            Field::DestIp => &p.dst_ip == value,
                            Field::SourcePort => p.src_port.to_string() == *value,
                            Field::DestPort => p.dst_port.to_string() == *value,
                            Field::TcpFlag => p.tcp_flags.to_string() == *value,
                            Field::Protocol => p.protocol.to_string() == *value,
                        };
                        if !pass {
                            break;
                        }
                    }
                    if pass {
                        current_packet = Some(p.clone());
                    } else {
                        current_packet = None;
                    }
                }
            }
            Operation::Map(_expr) => {
                if let Some(ref p) = current_packet {
                    current_packet = Some(PacketInfo {
                        src_ip: p.src_ip.clone(),
                        dst_ip: p.dst_ip.clone(),
                        src_port: p.src_port,
                        dst_port: p.dst_port,
                        tcp_flags: p.tcp_flags,
                        total_len: p.total_len,
                        protocol: p.protocol,
                    });
                }
            }
            Operation::Reduce { keys, function: _, reduce_type } => {
                if let Some(ref p) = current_packet {
                    let key = generate_key(p, keys);

                    match reduce_type {
                        ReduceType::CMReduce { memory_in_bytes, depth, seed } => {
                            let sketch_key = format!("CMSketch_{}_{}", memory_in_bytes, depth);
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_cm_sketch(*memory_in_bytes, *depth, *seed)
                            });
                            sketch.increment(&key, 1);
                            *ground_truth.entry(key.clone()).or_insert(0) += 1;
                        }
                        ReduceType::FCMReduce { depth, width, seed } => {
                            let sketch_key = format!("FCMSketch_{}_{}", depth, width);
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_fcm_sketch(*depth, *width, *seed)
                            });
                            sketch.increment(&key, 1);
                            *ground_truth.entry(key.clone()).or_insert(0) += 1;
                        }
                        ReduceType::ElasticReduce { depth, width, seed } => {
                            let sketch_key = format!("ElasticSketch_{}_{}", depth, width);
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_elastic_sketch(*depth, *width, *seed)
                            });
                            sketch.increment(&key, 1);
                            *ground_truth.entry(key.clone()).or_insert(0) += 1;
                        }
                        // Add other reduce types here in the future
                    }
                }
            }
            Operation::FilterResult(_expr) => {
                if let Some(ref p) = current_packet {
                    let count = sketches.values().map(|sketch| sketch.estimate(&p.src_ip)).max().unwrap_or(0);
                    if count >= threshold as u64 {
                        // println!("Packet passed filter result: src_ip: {}, count: {}", p.src_ip, count);
                    } else {
                        current_packet = None;
                    }
                }
            }
            Operation::Distinct(keys) => {
                if let Some(ref p) = current_packet {
                    let key = extract_key(p, keys);
                    if seen.contains(&key) {
                        current_packet = None;
                    } else {
                        seen.insert(key);
                    }
                }
            }
        }
    }
}

fn generate_key(packet: &PacketInfo, keys: &Vec<String>) -> String {
    keys.iter()
        .map(|key| packet.get(key).unwrap_or_else(|| "".to_string()))
        .collect::<Vec<String>>()
        .join("_")
}

fn extract_key(packet: &PacketInfo, keys: &Vec<String>) -> Vec<u8> {
    keys.iter().flat_map(|key| match key.as_str() {
        "src_ip" => packet.src_ip.as_bytes().to_vec(),
        "dst_ip" => packet.dst_ip.as_bytes().to_vec(),
        "src_port" => packet.src_port.to_be_bytes().to_vec(),
        "dst_port" => packet.dst_port.to_be_bytes().to_vec(),
        "total_len" => packet.total_len.to_be_bytes().to_vec(),
        _ => vec![],
    }).collect()
}