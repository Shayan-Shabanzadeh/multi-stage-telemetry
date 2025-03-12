use crate::query_plan::{QueryPlan, Operation, Field, ReduceType};
use crate::sketch::Sketch;
use std::collections::{HashMap, HashSet};
use std::io::Write;

#[derive(Clone, Debug)]
pub struct DynamicPacket {
    fields: Vec<PacketField>,
}

impl DynamicPacket {
    pub fn new(fields: Vec<PacketField>) -> Self {
        DynamicPacket { fields }
    }

    pub fn get_field(&self, index: usize) -> Option<&PacketField> {
        self.fields.get(index)
    }

    pub fn add_field(&mut self, field: PacketField) {
        self.fields.push(field);
    }
}

#[derive(Clone, Debug)]
pub enum PacketField {
    String(String),
    U16(u16),
    U8(u8),
    OptionU16(Option<u16>),
    OptionTupleU16(Option<(u16, u16)>),
}

pub fn execute_query(
    query: &QueryPlan,
    packet: DynamicPacket,
    sketches: &mut HashMap<String, Sketch>,
    ground_truth: &mut HashMap<String, u64>,
    results: &mut Vec<DynamicPacket>,
) -> Option<DynamicPacket> {
    let mut current_packet = Some(packet);

    for op in &query.operations {
        match op {
            Operation::Filter(conditions) => {
                if let Some(ref p) = current_packet {
                    let mut pass = true;
                    for (field, value) in conditions {
                        pass &= match field {
                            Field::SourceIp => match p.get_field(0) {
                                Some(PacketField::String(s)) => s == value,
                                _ => false,
                            },
                            Field::DestIp => match p.get_field(1) {
                                Some(PacketField::String(s)) => s == value,
                                _ => false,
                            },
                            Field::SourcePort => match p.get_field(2) {
                                Some(PacketField::U16(v)) => v.to_string() == *value,
                                _ => false,
                            },
                            Field::DestPort => match p.get_field(3) {
                                Some(PacketField::U16(v)) => v.to_string() == *value,
                                _ => false,
                            },
                            Field::TcpFlag => match p.get_field(4) {
                                Some(PacketField::U8(v)) => v.to_string() == *value,
                                _ => false,
                            },
                            Field::Protocol => match p.get_field(6) {
                                Some(PacketField::U8(v)) => v.to_string() == *value,
                                _ => false,
                            },
                            Field::DnsNsType => match p.get_field(7) {
                                Some(PacketField::OptionU16(v)) => v.map_or(false, |v| v.to_string() == *value),
                                _ => false,
                            },
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
                    let new_packet = map_packet(p, expr);
                    current_packet = Some(new_packet);
                }
            }
            Operation::Reduce { keys, function: _, reduce_type, index } => {
                if let Some(ref p) = current_packet {
                    let key = generate_key(p, keys);

                    match reduce_type {
                        ReduceType::CMReduce { memory_in_bytes, depth, seed } => {
                            let sketch_key = format!("CMSketch_{}_{}", memory_in_bytes, depth);
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_cm_sketch(*memory_in_bytes, *depth, *seed)
                            });

                            if let Some(count) = match p.get_field(*index) {
                                Some(PacketField::OptionU16(v)) => *v,
                                Some(PacketField::U16(v)) => Some(*v),
                                _ => None,
                            } {
                                sketch.increment(&key, count as u64);
                                *ground_truth.entry(key.clone()).or_insert(0) += count as u64;
                                // println!("ground_truth: {:?}", ground_truth);
                            } else {
                                eprintln!("Error reduce: Count value not found in tuple at index {}", index);
                                return None;
                            }

                            let new_count = sketch.estimate(&key);
                            current_packet = Some(update_packet_with_count(p, new_count, *index));
                        }
                        ReduceType::FCMReduce { depth, width, seed } => {
                            let sketch_key = format!("FCMSketch_{}_{}", depth, width);
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_fcm_sketch(*depth, *width, *seed)
                            });

                            if let Some(count) = match p.get_field(*index) {
                                Some(PacketField::OptionU16(v)) => *v,
                                Some(PacketField::U16(v)) => Some(*v),
                                _ => None,
                            } {
                                sketch.increment(&key, count as u64);
                                *ground_truth.entry(key.clone()).or_insert(0) += count as u64;
                            } else {
                                eprintln!("Error reduce: Count value not found in tuple at index {}", index);
                                return None;
                            }

                            let new_count = sketch.estimate(&key);
                            current_packet = Some(update_packet_with_count(p, new_count, *index));
                        }
                        ReduceType::ElasticReduce { depth, width, seed } => {
                            let sketch_key = format!("ElasticSketch_{}_{}", depth, width);
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_elastic_sketch(*depth, *width, *seed)
                            });

                            if let Some(count) = match p.get_field(*index) {
                                Some(PacketField::OptionU16(v)) => *v,
                                Some(PacketField::U16(v)) => Some(*v),
                                _ => None,
                            } {
                                sketch.increment(&key, count as u64);
                                *ground_truth.entry(key.clone()).or_insert(0) += count as u64;
                            } else {
                                eprintln!("Error reduce: Count value not found in tuple at index {}", index);
                                return None;
                            }

                            let new_count = sketch.estimate(&key);
                            current_packet = Some(update_packet_with_count(p, new_count, *index));
                        }
                        ReduceType::DeterministicReduce => {
                            let sketch_key = "DeterministicSketch".to_string();
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_deterministic_sketch()
                            });

                            if let Some(count) = match p.get_field(*index) {
                                Some(PacketField::OptionU16(v)) => *v,
                                Some(PacketField::U16(v)) => Some(*v),
                                _ => None,
                            } {
                                sketch.increment(&key, count as u64);
                                *ground_truth.entry(key.clone()).or_insert(0) += count as u64;
                            } else {
                                eprintln!("Error reduce: Count value not found in tuple at index {}", index);
                                return None;
                            }

                            let new_count = sketch.estimate(&key);
                            current_packet = Some(update_packet_with_count(p, new_count, *index));
                        }
                    }
                }
            }
            Operation::FilterResult { threshold, index } =>  {
                if let Some(ref p) = current_packet {
                    if let Some(count) = match p.get_field(*index) {
                        Some(PacketField::OptionU16(v)) => *v,
                        Some(PacketField::U16(v)) => Some(*v),
                        _ => None,
                    } {
                        if count >= *threshold as u16 {
                            // println!("FilterResult: {:?}", p);
                        } else {
                            current_packet = None;
                        }
                    } else {
                        eprintln!("Error filter result: Count value not found in tuple at index {}", index);
                        return None;
                    }
                }
            }
            Operation::Distinct { keys, distinct_type } => {
                if let Some(ref p) = current_packet {
                    let key = generate_key(p, keys);

                    match distinct_type {
                        ReduceType::CMReduce { memory_in_bytes, depth, seed } => {
                            let sketch_key = format!("DistinctCMSketch_{}_{}", memory_in_bytes, depth);
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_cm_sketch(*memory_in_bytes, *depth, *seed)
                            });

                            let current_count = sketch.estimate(&key);
                            if current_count > 0 {
                                current_packet = None;
                            }
                        }
                        ReduceType::FCMReduce { depth, width, seed } => {
                            let sketch_key = format!("DistinctFCMSketch_{}_{}", depth, width);
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_fcm_sketch(*depth, *width, *seed)
                            });

                            let current_count = sketch.estimate(&key);
                            if current_count > 0 {
                                current_packet = None;
                            }
                        }
                        ReduceType::ElasticReduce { depth, width, seed } => {
                            let sketch_key = format!("DistinctElasticSketch_{}_{}", depth, width);
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_elastic_sketch(*depth, *width, *seed)
                            });

                            let current_count = sketch.estimate(&key);
                            if current_count > 0 {
                                current_packet = None;
                            }
                        }
                        ReduceType::DeterministicReduce => {
                            let sketch_key = "DistinctDeterministicSketch".to_string();
                            let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                                Sketch::new_deterministic_sketch()
                            });

                            let current_count = sketch.estimate(&key);
                            if current_count > 0 {
                                current_packet = None;
                            }
                        }
                    }
                }
            }
            Operation::Join { left_query, right_query, join_keys } => {
                if let Some(ref p) = current_packet {
                    let mut left_results = Vec::new();
                    let left_result = execute_query(left_query, p.clone(), sketches, ground_truth, &mut left_results);
                    let mut right_results = Vec::new();
                    let right_result = execute_query(right_query, p.clone(), sketches, ground_truth, &mut right_results);

                    if let (Some(left_packet), Some(right_packet)) = (left_result, right_result) {
                        let joined_packet = join_packets(&left_packet, &right_packet, join_keys);
                        current_packet = Some(joined_packet);
                    } else {
                        current_packet = None;
                    }
                }
            }
        }
    }

    if let Some(ref p) = current_packet {
        results.push(p.clone());
    }

    current_packet
}

// pub fn summarize_epoch(
//     query: &QueryPlan,
//     timestamp: u64,
//     epoch_packets: usize,
//     total_packets: usize, 
//     flow_counts: &HashMap<(String, String, u16, u16, u8, u16, u8), u64>,
//     ground_truth: &HashMap<String, u64>, // Add ground_truth parameter
//     log_file: &mut std::fs::File,
// ) {
//     println!("Printing epoch summary...");
//     let mut summary = format!(
//         "Epoch end timestamp,Packets processed this epoch,Total packets processed\n{}, {}, {}\n",
//         timestamp, epoch_packets, total_packets
//     );

//     let mut valid_entries: Vec<((String, String, u16, u16, u8, u16, u8), u64)> = flow_counts.iter()
//         .filter(|&(_, &count)| {
//             query.operations.iter().any(|op| {
//                 if let Operation::FilterResult { threshold , index } = op {
//                     count > *threshold as u64
//                 } else {
//                     false
//                 }
//             })
//         })
//         .map(|(flow_key, &count)| (flow_key.clone(), count))
//         .collect();

//     // Sort by count in descending order
//     valid_entries.sort_by(|a, b| b.1.cmp(&a.1));

//     summary.push_str("Flow key,Count,Ground Truth\n");
//     for (flow_key, count) in &valid_entries {
//         let key_str = format!("{:?}", flow_key);
//         let ground_truth_count = ground_truth.get(&key_str).unwrap_or(&0);
//         let entry = format!("{:?},{},{}\n", flow_key, count, ground_truth_count);
//         summary.push_str(&entry);
//     }

//     if valid_entries.is_empty() {
//         summary.push_str("No entries exceeded the threshold.\n");
//     }

//     if let Err(e) = writeln!(log_file, "{}", summary.trim_end()) {
//         eprintln!("Failed to write to log file: {}", e);
//     } else {
//         println!("Successfully wrote to log file."); // Debugging statement
//     }
// }

fn map_packet(packet: &DynamicPacket, expr: &str) -> DynamicPacket {
    // println!("before Mapping packet: {:?}", packet);
    let parts: Vec<&str> = expr.trim_matches(|c| c == '(' || c == ')').split(',').map(|s| s.trim()).collect();
    let mut new_packet = DynamicPacket::new(vec![
        PacketField::String("".to_string()), // src_ip
        PacketField::String("".to_string()), // dst_ip
        PacketField::U16(0),                 // src_port
        PacketField::U16(0),                 // dst_port
        PacketField::U8(0),                  // tcp_flags
        PacketField::U16(0),                 // total_len
        PacketField::U8(0),                  // protocol
        PacketField::OptionU16(None),        // dns_ns_type
        PacketField::OptionU16(None),        // count1
        PacketField::OptionU16(None),        // count2
        PacketField::OptionU16(None),        // result
    ]);

    for part in parts {
        if part.starts_with("p.") {
            match part {
                "p.src_ip" => new_packet.fields[0] = packet.get_field(0).unwrap().clone(),
                "p.dst_ip" => new_packet.fields[1] = packet.get_field(1).unwrap().clone(),
                "p.src_port" => new_packet.fields[2] = packet.get_field(2).unwrap().clone(),
                "p.dst_port" => new_packet.fields[3] = packet.get_field(3).unwrap().clone(),
                "p.tcp_flags" => new_packet.fields[4] = packet.get_field(4).unwrap().clone(),
                "p.total_len" => new_packet.fields[5] = packet.get_field(5).unwrap().clone(),
                "p.protocol" => new_packet.fields[6] = packet.get_field(6).unwrap().clone(),
                "p.dns_ns_type" => new_packet.fields[7] = packet.get_field(7).unwrap().clone(),
                "p.count1" => new_packet.fields[8] = packet.get_field(8).unwrap().clone(),
                "p.count2" => new_packet.fields[9] = packet.get_field(9).unwrap().clone(),
                _ => {}
            }
        } else if part.contains('=') {
            let kv: Vec<&str> = part.split('=').map(|s| s.trim()).collect();
            if kv.len() == 2 {
                let key = kv[0];
                let value = kv[1];
                if key == "count" {
                    if value == "p.total_len" {
                        if let Some(PacketField::U16(total_len)) = packet.get_field(5) {
                            new_packet.fields[8] = PacketField::OptionU16(Some(*total_len));
                        }
                    } else if let Ok(count) = value.parse::<u16>() {
                        new_packet.fields[8] = PacketField::OptionU16(Some(count));
                    }
                }
            }
        } else if part.contains('/') {
            let kv: Vec<&str> = part.split('/').map(|s| s.trim()).collect();
            if kv.len() == 2 {
                let left = kv[0];
                let right = kv[1];
                if left == "count1" && right == "count2" {
                    if let (Some(PacketField::OptionU16(Some(count1))), Some(PacketField::OptionU16(Some(count2)))) =
                        (packet.get_field(8), packet.get_field(9))
                    {
                        if *count2 != 0 {
                            let result = *count1 / *count2;
                            new_packet.fields[10] = PacketField::OptionU16(Some(result));
                        }
                    }
                }
                // println!("new_packet: {:?}", new_packet);
            }
            
        }
    }
    // println!("after Mapping packet: {:?}", new_packet);

    new_packet
}

fn update_packet_with_count(packet: &DynamicPacket, count: u64, index: usize) -> DynamicPacket {
    let mut new_packet = packet.clone();
    if let Some(field) = new_packet.fields.get_mut(index) {
        *field = PacketField::OptionU16(Some(count as u16));
    } else {
        eprintln!("Error: Field at index {} not found in packet", index);
    }
    new_packet
}

fn generate_key(packet: &DynamicPacket, keys: &Vec<String>) -> String {
    keys.iter()
        .map(|key| match key.as_str() {
            "src_ip" => match packet.get_field(0) {
                Some(PacketField::String(s)) => s.clone(),
                _ => "".to_string(),
            },
            "dst_ip" => match packet.get_field(1) {
                Some(PacketField::String(s)) => s.clone(),
                _ => "".to_string(),
            },
            "src_port" => match packet.get_field(2) {
                Some(PacketField::U16(v)) => v.to_string(),
                _ => "".to_string(),
            },
            "dst_port" => match packet.get_field(3) {
                Some(PacketField::U16(v)) => v.to_string(),
                _ => "".to_string(),
            },
            "tcp_flags" => match packet.get_field(4) {
                Some(PacketField::U8(v)) => v.to_string(),
                _ => "".to_string(),
            },
            "total_len" => match packet.get_field(5) {
                Some(PacketField::U16(v)) => v.to_string(),
                _ => "".to_string(),
            },
            "protocol" => match packet.get_field(6) {
                Some(PacketField::U8(v)) => v.to_string(),
                _ => "".to_string(),
            },
            "dns_ns_type" => match packet.get_field(7) {
                Some(PacketField::OptionU16(v)) => v.map_or("".to_string(), |v| v.to_string()),
                _ => "".to_string(),
            },
            _ => "".to_string(),
        })
        .collect::<Vec<String>>()
        .join("_")
}

fn extract_key(packet: &DynamicPacket, keys: &Vec<String>) -> Vec<u8> {
    keys.iter().flat_map(|key| match key.as_str() {
        "src_ip" => match packet.get_field(0) {
            Some(PacketField::String(s)) => s.as_bytes().to_vec(),
            _ => vec![],
        },
        "dst_ip" => match packet.get_field(1) {
            Some(PacketField::String(s)) => s.as_bytes().to_vec(),
            _ => vec![],
        },
        "src_port" => match packet.get_field(2) {
            Some(PacketField::U16(v)) => v.to_be_bytes().to_vec(),
            _ => vec![],
        },
        "dst_port" => match packet.get_field(3) {
            Some(PacketField::U16(v)) => v.to_be_bytes().to_vec(),
            _ => vec![],
        },
        "total_len" => match packet.get_field(5) {
            Some(PacketField::U16(v)) => v.to_be_bytes().to_vec(),
            _ => vec![],
        },
        "dns_ns_type" => match packet.get_field(7) {
            Some(PacketField::OptionU16(v)) => v.map_or(vec![], |v| v.to_be_bytes().to_vec()),
            _ => vec![],
        },
        _ => vec![],
    }).collect()
}

fn join_packets(packet1: &DynamicPacket, packet2: &DynamicPacket, join_keys: &Vec<String>) -> DynamicPacket {
    // println!("packet1: {:?}", packet1);
    // println!("packet2: {:?}", packet2);
    let mut joined_packet = DynamicPacket::new(vec![
        PacketField::String("".to_string()), // src_ip
        PacketField::String("".to_string()), // dst_ip
        PacketField::U16(0),                 // src_port
        PacketField::U16(0),                 // dst_port
        PacketField::U8(0),                  // tcp_flags
        PacketField::U16(0),                 // total_len
        PacketField::U8(0),                  // protocol
        PacketField::OptionU16(None),        // dns_ns_type
        PacketField::OptionU16(None),        // count1
        PacketField::OptionU16(None),        // count2
        PacketField::OptionU16(None),        // result
    ]);

    // Add fields from packet1 based on join_keys
    for key in join_keys {
        match key.as_str() {
            "src_ip" => joined_packet.fields[0] = packet1.get_field(0).unwrap().clone(),
            "dst_ip" => joined_packet.fields[1] = packet1.get_field(1).unwrap().clone(),
            "src_port" => joined_packet.fields[2] = packet1.get_field(2).unwrap().clone(),
            "dst_port" => joined_packet.fields[3] = packet1.get_field(3).unwrap().clone(),
            "tcp_flags" => joined_packet.fields[4] = packet1.get_field(4).unwrap().clone(),
            "total_len" => joined_packet.fields[5] = packet1.get_field(5).unwrap().clone(),
            "protocol" => joined_packet.fields[6] = packet1.get_field(6).unwrap().clone(),
            "dns_ns_type" => joined_packet.fields[7] = packet1.get_field(7).unwrap().clone(),
            _ => {}
        }
    }

    // Add count from packet1
    if let Some(count1) = packet1.get_field(8) {
        joined_packet.fields[8] = count1.clone();
    }

    // Add count from packet2 as a new field
    if let Some(count2) = packet2.get_field(8) {
        joined_packet.fields[9] = count2.clone();
    }

    println!("joined packet: {:?}", joined_packet);
    joined_packet
}