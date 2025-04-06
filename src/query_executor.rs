use crate::query_plan::{QueryPlan, Operation, Field, ReduceType};
use crate::sketch::Sketch;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use crate::pcap_processor::EPOCH_RESULTS;


#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PacketField {
    String(String),
    U16(u16),
    U8(u8),
    OptionU16(Option<u16>),
    OptionTupleU16(Option<(u16, u16)>),
}
fn join_packets(
    left_packet: &HashMap<String, PacketField>,
    right_packet: &HashMap<String, PacketField>,
    left_keys: &[String],
    right_keys: &[String],
) -> Option<HashMap<String, PacketField>> {
    // Ensure the number of keys matches
    if left_keys.len() != right_keys.len() {
        eprintln!("Error: Mismatched number of left and right keys.");
        return None;
    }

    // Iterate over the key pairs and check if they match
    if left_keys.iter().zip(right_keys.iter()).all(|(left_key, right_key)| {
        match (left_packet.get(left_key), right_packet.get(right_key)) {
            (Some(left_value), Some(right_value)) => {
                // println!(
                //     "Checking left_key: {}, right_key: {}, left_value: {:?}, right_value: {:?}",
                //     left_key, right_key, left_value, right_value
                // );
                left_value == right_value
            }
            _ => {
                println!(
                    "Key mismatch: left_key: {}, right_key: {}, left_packet: {:?}, right_packet: {:?}",
                    left_key, right_key, left_packet, right_packet
                );
                false
            }
        }
    }) {
        // If all keys match, create the joined packet
        let mut joined_packet = left_packet.clone();
        for (key, value) in right_packet {
            joined_packet.entry(key.clone()).or_insert(value.clone());
        }
        // println!("Join successful. Joined packet: {:?}", joined_packet);
        Some(joined_packet)
    } else {
        // println!(
        //     "Join failed. left_packet: {:?}, right_packet: {:?}, left_keys: {:?}, right_keys: {:?}",
        //     left_packet, right_packet, left_keys, right_keys
        // );
        None
    }
}

fn evaluate_expression(expr: &str, result: &HashMap<String, PacketField>) -> Option<PacketField> {
    let tokens: Vec<&str> = expr.split_whitespace().collect();
    if tokens.len() == 3 {
        let left_operand = tokens[0];
        let operator = tokens[1];
        let right_operand = tokens[2];

        // Retrieve the values of the operands from the result map
        let left_value = get_field_value(left_operand, result)?;
        let right_value = get_field_value(right_operand, result)?;

        // Perform the operation
        match (left_value, right_value) {
            (PacketField::U16(left), PacketField::U16(right)) => match operator {
                "+" => Some(PacketField::U16(left + right)),
                "-" => Some(PacketField::U16(left.saturating_sub(right))),
                "*" => Some(PacketField::U16(left * right)),
                "/" => Some(PacketField::U16(if right != 0 { left / right } else { 0 })),
                _ => None,
            },
            (PacketField::U8(left), PacketField::U8(right)) => match operator {
                "+" => Some(PacketField::U8(left + right)),
                "-" => Some(PacketField::U8(left.saturating_sub(right))),
                "*" => Some(PacketField::U8(left * right)),
                "/" => Some(PacketField::U8(if right != 0 { left / right } else { 0 })),
                _ => None,
            },
            _ => None,
        }
    } else {
        eprintln!("Invalid expression format: {}", expr);
        None
    }
}

fn get_field_value(field: &str, result: &HashMap<String, PacketField>) -> Option<PacketField> {
    if let Some(value) = result.get(field) {
        Some(value.clone())
    } else {
        eprintln!("Field not found: {}", field);
        None
    }
}

pub fn execute_query(
    query: &QueryPlan,
    packet: HashMap<String, PacketField> ,
    sketches: &mut HashMap<String, Sketch>,
    ground_truth: &mut HashMap<String, (u64, u64)>,
    epoch_size: u64,
    current_epoch_start: &mut Option<u64>,
    timestamp: u64,
) -> Option<HashMap<String, PacketField>>  {
    let mut current_packet = packet;


    for op in &query.operations {
        if current_packet.is_empty() {
            eprintln!("Warning: Received an empty packet. Ignoring it.");
            return None;
        }
        match op {
            Operation::Filter(conditions) => {
                let mut pass = true;
                for (field, value) in conditions {
                    let field_key = match field {
                        Field::TcpFlag => "tcp_flags",
                        Field::SourceIp => "src_ip",
                        Field::DestIp => "dst_ip",
                        Field::SourcePort => "src_port",
                        Field::DestPort => "dst_port",
                        Field::Protocol => "protocol",
                        Field::DnsNsType => "DnsNsType"
                    };
            
                    pass &= match current_packet.get(field_key) {
                        Some(PacketField::String(s)) => s == value,
                        Some(PacketField::U16(v)) => v.to_string() == *value,
                        Some(PacketField::U8(v)) => v.to_string() == *value,
                        Some(PacketField::OptionU16(Some(v))) => v.to_string() == *value,
                        _ => false,
                    };
            
                    // Break early if a condition fails
                    if !pass {
                        break;
                    }
                }
            
                if !pass {
                    return None;
                }
                // println!("Packet passed filter: {:?}", current_packet);
            }
            Operation::Map(expr) => {
                // Parse the `expr` string into individual operations

                if current_packet.is_empty() {
                    return None;
                }

                let operations: Vec<&str> = expr
                    .trim_matches(|c| c == '(' || c == ')') // Remove parentheses
                    .split(',')                             // Split by commas
                    .map(|s| s.trim())                      // Trim whitespace
                    .collect();
            
                let mut new_packet: HashMap<String, PacketField> = HashMap::new();
            
                for operation in operations {
                    if operation.contains('=') {
                        let parts: Vec<&str> = operation.split('=').map(|s| s.trim()).collect();
                        if parts.len() == 2 {
                            let key = parts[0];
                            let value = parts[1];
            
                            if let Ok(parsed_value) = value.parse::<u16>() {
                                new_packet.insert(key.to_string(), PacketField::U16(parsed_value));
                            } else if let Ok(parsed_value) = value.parse::<u8>() {
                                new_packet.insert(key.to_string(), PacketField::U8(parsed_value));
                            } else {
                                new_packet.insert(key.to_string(), PacketField::String(value.to_string()));
                            }
                        }
                        
                    } else {
                        if let Some(value) = current_packet.get(operation) {
                            new_packet.insert(operation.to_string(), value.clone());
                        }
                    }
                }
                current_packet = new_packet;
            }


            Operation::Reduce { keys, reduce_type, field_name } => {
                let key = keys
                    .iter()
                    .map(|k| {
                        current_packet.get(k).map_or("".to_string(), |v| match v {
                            PacketField::String(s) => s.clone(),
                            PacketField::U16(v) => v.to_string(),
                            PacketField::U8(v) => v.to_string(),
                            PacketField::OptionU16(Some(v)) => v.to_string(),
                            _ => "".to_string(),
                        })
                    })
                    .collect::<Vec<_>>()
                    .join("_");
                let sketch_key = match reduce_type {
                    ReduceType::CMReduce { memory_in_bytes, depth, seed } => {
                        format!("CMSketch_{}_{}", memory_in_bytes, depth)
                    }

                    ReduceType::FCMReduce {
                        depth,
                        width_l1,
                        width_l2,
                        width_l3,
                        threshold_l1,
                        threshold_l2,
                        seed,
                    } => {
                        format!("FCMSketch_{}_{}", depth, width_l1)
                    }
                    ReduceType::ElasticReduce { depth, width, seed } => {
                        format!("ElasticSketch_{}_{}", depth, width)
                    }
                    ReduceType::DeterministicReduce => "DeterministicSketch".to_string(),
                    ReduceType::BloomFilter { .. } => {
                        eprintln!("Error: BloomFilter is not supported in Reduce operation");
                        return None;
                    }
                };
            
                let sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| match reduce_type {
                    ReduceType::CMReduce { memory_in_bytes, depth, seed } => {
                        Sketch::new_cm_sketch(*memory_in_bytes, *depth, *seed)
                    }
                    ReduceType::FCMReduce {
                        depth,
                        width_l1,
                        width_l2,
                        width_l3,
                        threshold_l1,
                        threshold_l2,
                        seed,
                    } => Sketch::new_fcm_sketch(
                        *depth,
                        *width_l1,
                        *width_l2,
                        *width_l3,
                        *threshold_l1,
                        *threshold_l2,
                        *seed,
                    ),
                    ReduceType::ElasticReduce { depth, width, seed } => {
                        Sketch::new_elastic_sketch(*depth, *width, *seed)
                    }
                    ReduceType::DeterministicReduce => Sketch::new_deterministic_sketch(),
                    ReduceType::BloomFilter { .. } => panic!("BloomFilter should not reach here"),
                });
            
                if let Some(PacketField::U16(current_value)) = current_packet.get(field_name) {
                    sketch.increment(&key, *current_value as u64);
                    let estimated_count = sketch.estimate(&key);
            
                    ground_truth
                        .entry(key.clone())
                        .and_modify(|e| {
                            e.0 += *current_value as u64;
                            e.1 = estimated_count;
                        })
                        .or_insert((*current_value as u64, estimated_count));
            
                    current_packet.insert(
                        field_name.to_string(),
                        PacketField::U16(estimated_count as u16),
                    );
                } else {
                    // eprintln!("Error reduce: field '{}' not found or invalid in packet", field_name);
                    return None;
                }
            }
            
            
            Operation::FilterResult { threshold, field_name } => {      
                if let Some(count) = match current_packet.get(field_name) {
                    Some(PacketField::OptionU16(Some(v))) => Some(*v),
                    Some(PacketField::U16(v)) => Some(*v),
                    _ => None,
                } {
                    if count < *threshold as u16 {
                        // The packet does not meet the threshold, discard it
                        current_packet.clear();
                    }
                } else {
                    eprintln!("Error filter result: Field '{}' not found or invalid in packet", field_name);
                    return None;
                }
            },
            Operation::Distinct { keys, distinct_type } => {
                // Generate a unique key for the group based on the specified keys
                let key = keys
                    .iter()
                    .map(|k| current_packet.get(k).map_or("".to_string(), |v| match v {
                        PacketField::String(s) => s.clone(),
                        PacketField::U16(v) => v.to_string(),
                        PacketField::U8(v) => v.to_string(),
                        PacketField::OptionU16(Some(v)) => v.to_string(),
                        _ => "".to_string(),
                    }))
                    .collect::<Vec<String>>()
                    .join("_");
                match distinct_type {
                    ReduceType::BloomFilter { expected_items, false_positive_rate } => {
                        let sketch_key = format!("DistinctBloomFilter_{}_{}", expected_items, false_positive_rate);
                        let bloom_filter = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                            Sketch::new_bloom_filter(*expected_items, *false_positive_rate)
                        });
            
                        if bloom_filter.contains(&key) {
                            current_packet.clear();
                            return None;
                        } else {
                            bloom_filter.insert(&key);
                        }
                    }
                    ReduceType::DeterministicReduce => {
                        let sketch_key = "DistinctDeterministicSketch".to_string();
                        let deterministic_sketch = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                            Sketch::new_deterministic_sketch()
                        });
            
                        let count = deterministic_sketch.estimate(&key);
                        if count > 0 {
                            current_packet.clear();
                            return None;
                        } else {
                            deterministic_sketch.increment(&key, 1);
                        }
                    }
                    _ => {
                        eprintln!("Unsupported distinct type");
                        return None;
                    }
                }
            }
            Operation::Join { left_query, right_query, left_keys, right_keys } => {
                // Static buffers for join
                static mut LEFT_RESULTS: Vec<HashMap<String, PacketField>> = Vec::new();
                static mut RIGHT_RESULTS: Vec<HashMap<String, PacketField>> = Vec::new();
                static mut JOIN_TIMESTAMP: Option<u64> = None;
            
                unsafe {
                    JOIN_TIMESTAMP.get_or_insert(timestamp);
            
                    if let Some(left_result) = execute_query(
                        left_query,
                        current_packet.clone(),
                        sketches,
                        ground_truth,
                        epoch_size,
                        current_epoch_start,
                        timestamp,
                    ) {
                        // println!("Left result: {:?}", left_result);
                        LEFT_RESULTS.push(left_result);
                    }
            
                    if let Some(right_result) = execute_query(
                        right_query,
                        current_packet.clone(),
                        sketches,
                        ground_truth,
                        epoch_size,
                        current_epoch_start,
                        timestamp,
                    ) {
                        RIGHT_RESULTS.push(right_result);
                    }
            
                    if timestamp - JOIN_TIMESTAMP.unwrap() >= epoch_size {
                        let mut joined_results = Vec::new();
                        // println!("LEFT_RESULTS size: {}", LEFT_RESULTS.len());
                        // println!("RIGHT_RESULTS size: {}", RIGHT_RESULTS.len());
                        for left_packet in &LEFT_RESULTS {
                            if left_packet.is_empty() {
                                continue;
                            }
            
                            for right_packet in &RIGHT_RESULTS {
                                if right_packet.is_empty() {
                                    continue;
                                }
                                if let Some(joined_packet) = join_packets(left_packet, right_packet, left_keys, right_keys) {
                                    if !joined_packet.is_empty() {
                                        joined_results.push(joined_packet.clone());
                                        // println!("Added to joined_results: {:?}", joined_packet);
                                    }
                                }
                            }
                        }
                        let mut epoch_results = EPOCH_RESULTS.lock().unwrap();
                        epoch_results.clear();
                        epoch_results.extend(joined_results.clone());
                        // println!("EPOCH_RESULTS: {:?}", epoch_results);
                        // Clear for next epoch
                        LEFT_RESULTS.clear();
                        RIGHT_RESULTS.clear();
                        JOIN_TIMESTAMP = Some(timestamp);
            
                        if joined_results.is_empty() {
                            return None;
                        } else {
                            // println!("Joined results: {:?}", joined_results);
                            current_packet = joined_results[0].clone();
                        }
                    } else {
                        // Skip join this time
                        return None;
                    }
                }
            }
            Operation::MapJoin(expr) => {
                let mut epoch_results = EPOCH_RESULTS.lock().unwrap();
                if epoch_results.is_empty() {
                    // println!("EPOCH_RESULTS is empty. Skipping MapJoin operation.");
                    continue;
                }
                let mut mapped_results = Vec::new();
            
                for result in epoch_results.iter() {
                    // println!("Result: {:?}", result);
                    let mut new_result = HashMap::new();
                    let operations: Vec<&str> = expr
                        .trim_matches(|c| c == '(' || c == ')')
                        .split(',')
                        .map(|s| s.trim())
                        .collect();
            
                    for operation in operations {
                        if operation.contains('=') {
                            let parts: Vec<&str> = operation.split('=').map(|s| s.trim()).collect();
                            if parts.len() == 2 {
                                let key = parts[0];
                                let value_expr = parts[1];
            
                                // Evaluate the expression (e.g., "left.count_left + right.count_right")
                                let evaluated_value = evaluate_expression(value_expr, result);
            
                                if let Some(evaluated_value) = evaluated_value {
                                    new_result.insert(key.to_string(), evaluated_value);
                                } else {
                                    eprintln!("Failed to evaluate expression: {}", value_expr);
                                }
                            }
                        } else {
                            if let Some(value) = result.get(operation) {
                                new_result.insert(operation.to_string(), value.clone());
                            }
                        }
                    }
                    mapped_results.push(new_result);
                }
            
                // Update EPOCH_RESULTS with the mapped results
                epoch_results.clear();
                epoch_results.extend(mapped_results);
                // println!("Mapped results: {:?}", epoch_results);
            }
            
            
        }
    }

    Some(current_packet)
}
