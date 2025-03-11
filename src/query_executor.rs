use crate::query_plan::{QueryPlan, Operation, Field, ReduceType};
use crate::sketch::Sketch;
use std::collections::{HashMap, HashSet};

pub fn execute_query(query: &QueryPlan, packet: (String, String, u16, u16, u8, u16, u8, Option<u16>), threshold: usize, sketches: &mut HashMap<String, Sketch>, ground_truth: &mut HashMap<String, u64>) {
    let mut current_packet = Some(packet);
    let mut seen = HashSet::new();

    for op in &query.operations {
        match op {
            Operation::Filter(conditions) => {
                if let Some(ref p) = current_packet {
                    let mut pass = true;
                    for (field, value) in conditions {
                        pass &= match field {
                            Field::SourceIp => &p.0 == value,
                            Field::DestIp => &p.1 == value,
                            Field::SourcePort => p.2.to_string() == *value,
                            Field::DestPort => p.3.to_string() == *value,
                            Field::TcpFlag => p.4.to_string() == *value,
                            Field::Protocol => p.6.to_string() == *value,
                            Field::DnsNsType => p.7.map_or(false, |v| v.to_string() == *value),
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
                    current_packet = Some((
                        p.0.clone(),
                        p.1.clone(),
                        p.2,
                        p.3,
                        p.4,
                        p.5,
                        p.6,
                        p.7,
                    ));
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
                    let count = sketches.values().map(|sketch| sketch.estimate(&p.0)).max().unwrap_or(0);
                    if count >= threshold as u64 {
                        // println!("Packet passed filter result: src_ip: {}, count: {}", p.0, count);
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

fn generate_key(packet: &(String, String, u16, u16, u8, u16, u8, Option<u16>), keys: &Vec<String>) -> String {
    keys.iter()
        .map(|key| match key.as_str() {
            "src_ip" => packet.0.clone(),
            "dst_ip" => packet.1.clone(),
            "src_port" => packet.2.to_string(),
            "dst_port" => packet.3.to_string(),
            "tcp_flags" => packet.4.to_string(),
            "total_len" => packet.5.to_string(),
            "protocol" => packet.6.to_string(),
            "dns_ns_type" => packet.7.map_or("".to_string(), |v| v.to_string()),
            _ => "".to_string(),
        })
        .collect::<Vec<String>>()
        .join("_")
}

fn extract_key(packet: &(String, String, u16, u16, u8, u16, u8, Option<u16>), keys: &Vec<String>) -> Vec<u8> {
    keys.iter().flat_map(|key| match key.as_str() {
        "src_ip" => packet.0.as_bytes().to_vec(),
        "dst_ip" => packet.1.as_bytes().to_vec(),
        "src_port" => packet.2.to_be_bytes().to_vec(),
        "dst_port" => packet.3.to_be_bytes().to_vec(),
        "total_len" => packet.5.to_be_bytes().to_vec(),
        "dns_ns_type" => packet.7.map_or(vec![], |v| v.to_be_bytes().to_vec()),
        _ => vec![],
    }).collect()
}