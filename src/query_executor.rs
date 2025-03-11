use crate::query_plan::{QueryPlan, Operation, Field, ReduceType};
use crate::sketch::Sketch;
use std::collections::{HashMap, HashSet};

pub fn execute_query(query: &QueryPlan, packet: (String, String, u16, u16, u8, u16, u8, Option<u16>), threshold: usize, sketches: &mut HashMap<String, Sketch>, ground_truth: &mut HashMap<String, u64>) -> Option<(String, String, u16, u16, u8, u16, u8, Option<u16>)> {
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
            Operation::Map(expr) => {
                if let Some(ref p) = current_packet {
                    // println!("Before Map: {:?}", p);
                    let new_tuple = map_packet(p, expr);
                    // println!("After Map: {:?}", new_tuple);
                    current_packet = Some(new_tuple);
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

                            // Get the current count from the sketch
                            let current_count = sketch.estimate(&key);

                            // Update the sketch with the new count
                            if let Some(count) = p.7 {
                                sketch.increment(&key, count as u64);
                            } else {
                                eprintln!("Error: Count value not found in tuple");
                                return None;
                            }

                            // Update the tuple with the new count
                            let new_count = current_count + p.7.unwrap() as u64;
                            current_packet = Some(update_tuple_with_count(p, new_count));
                        }
                        ReduceType::FCMReduce { depth, width, seed } => {
                            let sketch_key = format!("FCMSketch_{}_{}", depth, width);
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_fcm_sketch(*depth, *width, *seed)
                            });

                            // Get the current count from the sketch
                            let current_count = sketch.estimate(&key);

                            // Update the sketch with the new count
                            if let Some(count) = p.7 {
                                sketch.increment(&key, count as u64);
                            } else {
                                eprintln!("Error: Count value not found in tuple");
                                return None;
                            }

                            // Update the tuple with the new count
                            let new_count = current_count + p.7.unwrap() as u64;
                            current_packet = Some(update_tuple_with_count(p, new_count));
                        }
                        ReduceType::ElasticReduce { depth, width, seed } => {
                            let sketch_key = format!("ElasticSketch_{}_{}", depth, width);
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_elastic_sketch(*depth, *width, *seed)
                            });

                            // Get the current count from the sketch
                            let current_count = sketch.estimate(&key);

                            // Update the sketch with the new count
                            if let Some(count) = p.7 {
                                sketch.increment(&key, count as u64);
                            } else {
                                eprintln!("Error: Count value not found in tuple");
                                return None;
                            }

                            // Update the tuple with the new count
                            let new_count = current_count + p.7.unwrap() as u64;
                            current_packet = Some(update_tuple_with_count(p, new_count));
                        }
                        ReduceType::DeterministicReduce => {
                            let sketch_key = "DeterministicSketch".to_string();
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_deterministic_sketch()
                            });

                            // Get the current count from the sketch
                            let current_count = sketch.estimate(&key);

                            // Update the sketch with the new count
                            if let Some(count) = p.7 {
                                sketch.increment(&key, count as u64);
                            } else {
                                eprintln!("Error: Count value not found in tuple");
                                return None;
                            }

                            // Update the tuple with the new count
                            let new_count = current_count + p.7.unwrap() as u64;
                            current_packet = Some(update_tuple_with_count(p, new_count));
                        }
                    }
                }
            }
            Operation::FilterResult(_expr) => {
                if let Some(ref p) = current_packet {
                    if let Some(count) = p.7 {
                        // println!("FilterResult: {:?} and count: {}", p, count);
                        if count >= threshold as u16 {
                            // println!("Packet passed filter result: {:?}", p);
                        } else {
                            current_packet = None;
                        }
                    } else {
                        eprintln!("Error: Count value not found in tuple");
                        return None;
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
            Operation::Join(other_query, join_keys) => {
                if let Some(ref p) = current_packet {
                    let other_result = execute_query(other_query, p.clone(), sketches, ground_truth);
                    if let Some(other_packet) = other_result {
                        let joined_packet = join_packets(p, &other_packet, join_keys);
                        current_packet = Some(joined_packet);
                        // println!("Joined packet: {:?}", current_packet);
                    } else {
                        current_packet = None;
                    }
                }
            }
        }
    }

    current_packet
}

fn map_packet(packet: &(String, String, u16, u16, u8, u16, u8, Option<u16>), expr: &str) -> (String, String, u16, u16, u8, u16, u8, Option<u16>) {
    // Parse the expression and create a new tuple based on the expression
    // Example expressions:
    // "(p.dst_ip, 1)"
    // "(p.dst_ip, p.src_ip)"
    // "(p.src_ip)"
    let parts: Vec<&str> = expr.trim_matches(|c| c == '(' || c == ')').split(',').map(|s| s.trim()).collect();
    let mut new_tuple = ("".to_string(), "".to_string(), 0, 0, 0, 0, 0, None);

    for (i, part) in parts.iter().enumerate() {
        match *part {
            "p.src_ip" => new_tuple.0 = packet.0.clone(),
            "p.dst_ip" => new_tuple.1 = packet.1.clone(),
            "p.src_port" => new_tuple.2 = packet.2,
            "p.dst_port" => new_tuple.3 = packet.3,
            "p.tcp_flags" => new_tuple.4 = packet.4,
            "p.total_len" => new_tuple.5 = packet.5,
            "p.protocol" => new_tuple.6 = packet.6,
            "1" => new_tuple.7 = Some(1),
            _ => {}
        }
    }

    new_tuple
}

fn update_tuple_with_count(packet: &(String, String, u16, u16, u8, u16, u8, Option<u16>), count: u64) -> (String, String, u16, u16, u8, u16, u8, Option<u16>) {
    (
        packet.0.clone(),
        packet.1.clone(),
        packet.2,
        packet.3,
        packet.4,
        packet.5,
        packet.6,
        Some(count as u16),
    )
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

fn join_packets(packet1: &(String, String, u16, u16, u8, u16, u8, Option<u16>), packet2: &(String, String, u16, u16, u8, u16, u8, Option<u16>), join_keys: &Vec<String>) -> (String, String, u16, u16, u8, u16, u8, Option<u16>) {
    let mut joined_packet = packet1.clone();
    for key in join_keys {
        match key.as_str() {
            "src_ip" => joined_packet.0 = packet2.0.clone(),
            "dst_ip" => joined_packet.1 = packet2.1.clone(),
            "src_port" => joined_packet.2 = packet2.2,
            "dst_port" => joined_packet.3 = packet2.3,
            "tcp_flags" => joined_packet.4 = packet2.4,
            "total_len" => joined_packet.5 = packet2.5,
            "protocol" => joined_packet.6 = packet2.6,
            "dns_ns_type" => joined_packet.7 = packet2.7,
            _ => {}
        }
    }
    joined_packet
}