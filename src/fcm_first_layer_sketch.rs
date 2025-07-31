use std::collections::HashSet;
use crate::bobhash32::BOBHash32;


type FCMSK_C1 = u32; // counter type is 32 bits like Count-Min sketch


// This FCM only uses the first layer of the FCM sketch and does not have any pormotion.
pub struct FCMFirstLayerOnly {
    pub depth: usize,
    pub width_l1: usize,
    pub counters_l1: Vec<Vec<FCMSK_C1>>,
    pub hash_functions: Vec<BOBHash32>,
}

impl FCMFirstLayerOnly {
    pub fn new(depth: usize, width_l1: usize, seed: u64) -> Self {
        let mut hash_functions = Vec::with_capacity(depth);
        for i in 0..depth {
            hash_functions.push(BOBHash32::new((seed as u32) + i as u32));
        }

        Self {
            depth,
            width_l1,
            counters_l1: vec![vec![0; width_l1]; depth],
            hash_functions,
        }
    }

    pub fn insert(&mut self, item: &[u8], count: u32) {
        for d in 0..self.depth {
            let index = self.hash_functions[d].run(item) as usize % self.width_l1;
            self.counters_l1[d][index] = self.counters_l1[d][index].saturating_add(count);
        }
    }

    pub fn query(&self, item: &[u8]) -> u32 {
        let mut ret = u32::MAX;
        for d in 0..self.depth {
            let index = self.hash_functions[d].run(item) as usize % self.width_l1;
            ret = ret.min(self.counters_l1[d][index]);
        }
        ret
    }
}