use std::collections::HashSet;
use crate::bobhash32::BOBHash32;

const FCMSK_K_ARY: usize = 8; // k-ary tree
const FCMSK_K_POW: usize = 3; // 2^3 = 8
const HH_THRESHOLD: u32 = 10000; // Heavy hitter threshold

    type FCMSK_C1 = u32;  // 8-bit
    type FCMSK_C2 = u32; // 16-bit
    type FCMSK_C3 = u32; // 32-bit

pub struct FCMSketch {
    pub depth: usize,
    pub width_l1: usize,
    pub width_l2: usize,
    pub width_l3: usize,
    pub threshold_l1: u32,
    pub threshold_l2: u32,
    pub counters_l1: Vec<Vec<FCMSK_C1>>,
    pub counters_l2: Vec<Vec<FCMSK_C2>>,
    pub counters_l3: Vec<Vec<FCMSK_C3>>,
    pub hash_functions: Vec<BOBHash32>,
    pub hh_candidates: HashSet<u32>,
    pub cumul_l2: u32,
    pub cumul_l3: u32,
}

impl FCMSketch {
    pub fn new(depth: usize, width_l1: usize, width_l2: usize, width_l3: usize, threshold_l1: u32, threshold_l2: u32, seed: u64) -> Self {
        let mut hash_functions = Vec::with_capacity(depth);
        for i in 0..depth {
            hash_functions.push(BOBHash32::new((seed as u32) + i as u32));
        }

        Self {
            depth,
            width_l1,
            width_l2,
            width_l3,
            threshold_l1,
            threshold_l2,
            counters_l1: vec![vec![0; width_l1]; depth],
            counters_l2: vec![vec![0; width_l2]; depth],
            counters_l3: vec![vec![0; width_l3]; depth],
            hash_functions,
            hh_candidates: HashSet::new(),
            cumul_l2: threshold_l1,
            cumul_l3: threshold_l1 + threshold_l2,
        }
    }

    pub fn insert(&mut self, item: &[u8], count: u32) {
        let mut hash_index = vec![0; self.depth];
        let mut ret_val = vec![0; self.depth];
        let mut hh_flag = true;
    
        // Define the target item
        let target_item = "dst_ip: 35.26.185.176, src_ip: 163.27.199.6".as_bytes();
        let is_target_item = item == target_item;
    
        // if is_target_item {
        //     println!("[DEBUG] Target item detected: dst_ip: 35.26.185.176, src_ip: 163.27.199.6 with count {:?}", count);
        // }
    
        // Compute hash indices for each depth
        for d in 0..self.depth {
            hash_index[d] = self.hash_functions[d].run(item) as usize % self.width_l1;
    
            // if is_target_item {
            //     println!(
            //         "[DEBUG] Depth {}: Hash index for L1 = {}",
            //         d, hash_index[d]
            //     );
            // }
        }
    
        for d in 0..self.depth {
            let mut idx = hash_index[d];
    
            // Stage 1: L1
            ret_val[d] = self.increment_counter_l1(d, idx, count);
    
            // if is_target_item {
            //     println!(
            //         "[DEBUG] Depth {}: L1 Counter[{}] = {} after increment",
            //         d, idx, self.counters_l1[d][idx]
            //     );
            // }
    
            if ret_val[d] <= self.threshold_l1 {
                // Did not overflow, done
                continue;
            }
    
            // Stage 2: L2
            idx = idx / FCMSK_K_ARY;
            ret_val[d] = self.increment_counter_l2(d, idx, count) + self.cumul_l2;
    
            // if is_target_item {
            //     println!(
            //         "[DEBUG] Depth {}: L2 Counter[{}] = {} after increment",
            //         d, idx, self.counters_l2[d][idx]
            //     );
            // }
    
            if ret_val[d] <= self.threshold_l2 {
                continue;
            }
    
            // Stage 3: L3
            idx = idx / FCMSK_K_ARY;
            ret_val[d] = self.increment_counter_l3(d, idx, count) + self.cumul_l3;
    
            // if is_target_item {
            //     println!(
            //         "[DEBUG] Depth {}: L3 Counter[{}] = {} after increment",
            //         d, idx, self.counters_l3[d][idx]
            //     );
            // }
        }
    
        // Check if the item qualifies as a heavy hitter
        for d in 0..self.depth {
            if ret_val[d] <= HH_THRESHOLD {
                hh_flag = false;
                break;
            }
        }
    
        if hh_flag {
            if item.len() == 4 {
                let item_u32 = u32::from_be_bytes(item.try_into().unwrap());
                self.hh_candidates.insert(item_u32);
    
                // if is_target_item {
                //     println!("[DEBUG] Heavy hitter detected: {:?}", item_u32);
                // }
            }
        }
    }
    
    pub fn query(&self, item: &[u8]) -> u32 {
        let mut hash_index = vec![0; self.depth];
        let mut ret_val = vec![0; self.depth];
        let mut count_query = u32::MAX;
    
        // Define the target item
        let target_item = "dst_ip: 35.26.185.176, src_ip: 163.27.199.6".as_bytes();
        let is_target_item = item == target_item;
    
        // if is_target_item {
        //     println!("[DEBUG] Querying target item: dst_ip: 35.26.185.176, src_ip: 163.27.199.6");
        // }
    
        // Compute hash indices for each depth
        for d in 0..self.depth {
            hash_index[d] = self.hash_functions[d].run(item) as usize % self.width_l1;
    
            // if is_target_item {
            //     println!(
            //         "[DEBUG] Depth {}: Hash index for L1 = {}",
            //         d, hash_index[d]
            //     );
            // }
        }
    
        for d in 0..self.depth {
            let mut idx = hash_index[d];
    
            // Stage 1: L1
            ret_val[d] = self.query_counter_l1(d, idx);
    
            // if is_target_item {
            //     println!(
            //         "[DEBUG] Depth {}: L1 Counter[{}] = {}",
            //         d, idx, self.counters_l1[d][idx]
            //     );
            // }
    
            if ret_val[d] <= self.threshold_l1 {
                count_query = count_query.min(ret_val[d]);
                continue;
            }
    
            // Stage 2: L2
            idx = idx / FCMSK_K_ARY;
            ret_val[d] = self.query_counter_l2(d, idx) + self.cumul_l2;
    
            // if is_target_item {
            //     println!(
            //         "[DEBUG] Depth {}: L2 Counter[{}] = {}",
            //         d, idx, self.counters_l2[d][idx]
            //     );
            // }
    
            if ret_val[d] <= self.threshold_l2 {
                count_query = count_query.min(ret_val[d]);
                continue;
            }
    
            // Stage 3: L3
            idx = idx / FCMSK_K_ARY;
            ret_val[d] = self.query_counter_l3(d, idx) + self.cumul_l3;
    
            // if is_target_item {
            //     println!(
            //         "[DEBUG] Depth {}: L3 Counter[{}] = {}",
            //         d, idx, self.counters_l3[d][idx]
            //     );
            // }
    
            count_query = count_query.min(ret_val[d]);
        }
    
        // if is_target_item {
        //     println!("[DEBUG] Final query result for target item: {}", count_query);
        // }
    
        count_query
    }
    

    pub fn get_cardinality(&self) -> i32 {
        let mut avgnum_empty_counter = 0;
        for d in 0..self.depth {
            avgnum_empty_counter += self.counters_l1[d].iter().filter(|&&x| x == 0).count();
        }
        (self.width_l1 as f64 * (self.width_l1 as f64 / avgnum_empty_counter as f64).ln()) as i32
    }

    fn increment_counter_l1(&mut self, depth: usize, index: usize, count: u32) -> u32 {
        let old_val = self.counters_l1[depth][index];
        let new_val = old_val.saturating_add(count as FCMSK_C1);
        self.counters_l1[depth][index] = new_val;
        new_val as u32
    }

    fn increment_counter_l2(&mut self, depth: usize, index: usize, count: u32) -> u32 {
        let old_val = self.counters_l2[depth][index];
        let new_val = old_val.saturating_add(count as FCMSK_C2);
        self.counters_l2[depth][index] = new_val;
        new_val as u32
    }

    fn increment_counter_l3(&mut self, depth: usize, index: usize, count: u32) -> u32 {
        let old_val = self.counters_l3[depth][index];
        let new_val = old_val.saturating_add(count as FCMSK_C3);
        self.counters_l3[depth][index] = new_val;
        new_val as u32
    }

    fn query_counter_l1(&self, depth: usize, index: usize) -> u32 {
        self.counters_l1[depth][index] as u32
    }

    fn query_counter_l2(&self, depth: usize, index: usize) -> u32 {
        self.counters_l2[depth][index] as u32
    }

    fn query_counter_l3(&self, depth: usize, index: usize) -> u32 {
        self.counters_l3[depth][index] as u32
    }
}