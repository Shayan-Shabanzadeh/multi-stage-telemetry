use crate::query_plan::{QueryPlan, Operation, Field, ReduceType};
use crate::sketch::Sketch;
use std::collections::{HashMap};
use crate::pcap_processor::EPOCH_RESULTS;
use lazy_static::lazy_static;
use std::sync::Mutex;




lazy_static! {
    static ref LEFT_RESULTS: Mutex<HashMap<String, HashMap<String, PacketField>>> = Mutex::new(HashMap::new());
    static ref RIGHT_RESULTS: Mutex<HashMap<String, HashMap<String, PacketField>>> = Mutex::new(HashMap::new());
}


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
        println!("Join successful. Joined packet: {:?}", joined_packet);
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
    packet: HashMap<String, PacketField>,
    sketches: &mut HashMap<String, Sketch>,
    result_map: &mut HashMap<String, HashMap<String, PacketField>>,
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
                    current_packet.get(k).map_or(format!("{}: <missing>", k), |v| match v {
                        PacketField::String(s) => format!("{}: {}", k, s),
                        PacketField::U16(v) => format!("{}: {}", k, v),
                        PacketField::U8(v) => format!("{}: {}", k, v),
                        PacketField::OptionU16(Some(v)) => format!("{}: {}", k, v),
                        _ => format!("{}: <invalid>", k),
                    })
                })
                .collect::<Vec<_>>()
                .join(", ");
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

                    current_packet.insert(
                        field_name.to_string(),
                        PacketField::U16(estimated_count as u16),
                    );

                    result_map
                    .entry(key.clone())
                    .and_modify(|existing_packet| {
                        for (field_key, field_value) in &current_packet {
                            existing_packet.insert(field_key.clone(), field_value.clone());
                        }
                    })
                    .or_insert(current_packet.clone()); // Insert the entire packet if the key doesn't exist
            
                } else {
                    // eprintln!("Error reduce: field '{}' not found or invalid in packet", field_name);
                    return None;
                }
            }
            
            
            Operation::FilterResult { threshold, field_name } => {
                // println!("timestamp: {}, current_epoch_start: {:?}", timestamp, current_epoch_start);
                if timestamp - current_epoch_start.unwrap() >= epoch_size  {
                    result_map.retain(|key, fields| {
                        // println!("Checking key: '{}', fields: {:?}", key, fields);
                        if let Some(PacketField::U16(value)) = fields.get(field_name) {
                            if *value >= *threshold as u16 {
                                true // Keep the entry
                            } else {
                                false // Remove the entry
                            }
                        } else {
                            eprintln!(
                                "Error filter result: Field '{}' not found or invalid in entry '{}'",
                                field_name, key
                            );
                            false // Remove the entry if the field is missing or invalid
                        }
                    });
                
                }
            },
            Operation::Distinct { keys, distinct_type } => {
                // Generate a unique key for the group based on the specified keys
                let key = keys
                .iter()
                .map(|k| {
                    current_packet.get(k).map_or(format!("{}: <missing>", k), |v| match v {
                        PacketField::String(s) => format!("{}: {}", k, s),
                        PacketField::U16(v) => format!("{}: {}", k, v),
                        PacketField::U8(v) => format!("{}: {}", k, v),
                        PacketField::OptionU16(Some(v)) => format!("{}: {}", k, v),
                        _ => format!("{}: <invalid>", k),
                    })
                })
                .collect::<Vec<_>>()
                .join(", ");
                match distinct_type {
                    ReduceType::BloomFilter { size, num_hashes, seed } => {
                        let sketch_key = format!("DistinctBloomFilter_{}_{}", size, num_hashes);
                        let bloom_filter = sketches.entry(sketch_key.clone()).or_insert_with(|| {
                            Sketch::new_bloom_filter(*size, *num_hashes, *seed)
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

                let mut join_timestamp: Option<u64> = None;
                join_timestamp.get_or_insert(timestamp);
            
                // Execute the left query
                {
                    let mut left_results = LEFT_RESULTS.lock().unwrap();
                    execute_query(
                        left_query,
                        current_packet.clone(),
                        sketches,
                        &mut left_results, 
                        epoch_size,
                        current_epoch_start,
                        timestamp,
                    );
                }
            
                // Execute the right query
                {
                    let mut right_results = RIGHT_RESULTS.lock().unwrap();
                    execute_query(
                        right_query,
                        current_packet.clone(),
                        sketches,
                        &mut right_results,
                        epoch_size,
                        current_epoch_start,
                        timestamp,
                    );
                }

            
                if timestamp - current_epoch_start.unwrap() >= epoch_size -1 {
                    println!("Join operation triggered at timestamp: {}", timestamp);

                    let mut joined_results: HashMap<String, HashMap<String, PacketField>> = HashMap::new();
                        
                    // Lock both LEFT_RESULTS and RIGHT_RESULTS in a consistent order
                    let (left_results, right_results) = {
                        let left_results = LEFT_RESULTS.lock().unwrap();
                        let right_results = RIGHT_RESULTS.lock().unwrap();
                        (left_results.clone(), right_results.clone()) // Clone to avoid holding locks during iteration
                    };
            
                    for (left_key, left_fields) in &left_results {
                        for (right_key, right_fields) in &right_results {

                            if left_keys.iter().zip(right_keys.iter()).all(|(left_field, right_field)| {
                                match (left_fields.get(left_field), right_fields.get(right_field)) {
                                    (Some(left_value), Some(right_value)) => {
                                        left_value == right_value
                                    }
                                    _ => {
                                        println!(
                                            "Fields do not match - left_field: {}, right_field: {}, left_value: {:?}, right_value: {:?}",
                                            left_field, right_field, left_fields.get(left_field), right_fields.get(right_field)
                                        );
                                        false
                                    }
                                }
                            }) {
                                // println!("Fields matched for left_key: {} and right_key: {}", left_key, right_key);
            
                                // Perform the join operation
                                let mut joined_fields = left_fields.clone();
                                for (key, value) in right_fields {
                                    // println!("Adding field to joined_fields - key: {}, value: {:?}", key, value);
                                    joined_fields.entry(key.clone()).or_insert(value.clone());
                                }
            
                                // Add the joined result to the final results
                                joined_results.insert(left_key.clone(), joined_fields);
                                // println!("join result: {:?}", joined_results);

                            }
                        }
                    }

                    // println!("join result :{:?}" , joined_results);


                    result_map.clear();
                    result_map.extend(joined_results);
                    // println!("result map: {:?}", result_map);
            
                    // Clear for the next epoch
                    {
                        let mut left_results = LEFT_RESULTS.lock().unwrap();
                        let mut right_results = RIGHT_RESULTS.lock().unwrap();
                        left_results.clear();
                        right_results.clear();
                    }
            
                    join_timestamp = Some(timestamp);
                } else {
                    return None;
                }
            }
            Operation::MapJoin(expr) => {
                if timestamp - current_epoch_start.unwrap_or(0) >= epoch_size {
            
                    let mut mapped_results = HashMap::new();
            
                    for (key, result) in result_map.iter() {
                        // println!("Processing result for key: {:?}, value: {:?}", key, result);
            
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
                        mapped_results.insert(key.clone(), new_result);

                    }

                    // println!("result map: {:?}", result_map);
            
                    // Clear and update result_map with the mapped results
                    result_map.clear();
                    result_map.extend(mapped_results);
            
                } else {
                    println!("Epoch not reached. Skipping MapJoin operation.");
                }
            }
            Operation::FilterJoin { threshold, field_name } => {
                let mut epoch_results = EPOCH_RESULTS.lock().unwrap();
                if epoch_results.is_empty() {
                    // println!("EPOCH_RESULTS is empty. Skipping FilterJoin operation.");
                    continue;
                }

                // println!("EPOCH_RESULTS : {:?}", epoch_results);    
                // println!("------------------------");
            
                epoch_results.retain(|result| {
                    if let Some(PacketField::U16(count)) = result.get(field_name) {
                        if *count >= *threshold {
                            true 
                        } else {
                            // println!(
                            //     "Filtered out result: {:?} (count: {}, threshold: {})",
                            //     result, count, threshold
                            // );
                            false
                        }
                    } else {
                        println!(
                            "Field '{}' not found or invalid in result: {:?}",
                            field_name, result
                        );
                        false
                    }
                });
            
                // println!("Filtered EPOCH_RESULTS: {:?}", epoch_results);
            }
            
            
        }
    }

    Some(current_packet)
}
