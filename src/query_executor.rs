use crate::query_plan::{QueryPlan, Operation, Field, ReduceType};
use crate::packet_info::PacketInfo;
use crate::sketch::Sketch;
use std::collections::HashMap;

pub fn execute_query(query: &QueryPlan, packet: PacketInfo, threshold: usize, sketches: &mut HashMap<String, Sketch>, ground_truth: &mut HashMap<String, u64>) {
    let mut current_packet = Some(packet);

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
                    });
                }
            }
            Operation::Reduce { keys: _, function: _, reduce_type } => {
                if let Some(ref p) = current_packet {
                    match reduce_type {
                        ReduceType::CMReduce { memory_in_bytes, depth, seed } => {
                            let sketch_key = format!("CMSketch_{}_{}", memory_in_bytes, depth);
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_cm_sketch(*memory_in_bytes, *depth, *seed)
                            });
                            sketch.increment(&p.dst_ip, 1);
                            *ground_truth.entry(p.dst_ip.clone()).or_insert(0) += 1;
                        }
                        ReduceType::FCMReduce { depth, width, seed } => {
                            let sketch_key = format!("FCMSketch_{}_{}", depth, width);
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_fcm_sketch(*depth, *width, *seed)
                            });
                            sketch.increment(&p.dst_ip, 1);
                            *ground_truth.entry(p.dst_ip.clone()).or_insert(0) += 1;
                        }
                        // Add other reduce types here in the future
                    }
                }
            }
            Operation::FilterResult(_expr) => {
                if let Some(ref p) = current_packet {
                    let count = sketches.values().map(|sketch| sketch.estimate(&p.dst_ip)).max().unwrap_or(0);
                    if count >= threshold as u64 {
                        println!("Packet passed filter result: dst_ip: {}, count: {}", p.dst_ip, count);
                    } else {
                        current_packet = None;
                    }
                }
            }
        }
    }
}