use std::collections::HashSet;
use std::convert::TryInto;

pub struct FCMSketch {
    pub depth: usize,
    pub width: usize,
    pub counters: Vec<Vec<u32>>,
    pub hash_seeds: Vec<u32>,
    pub hh_candidates: HashSet<u32>,
    pub cumul_l2: u32,
    pub cumul_l3: u32,
}

impl FCMSketch {
    pub fn new(depth: usize, width: usize, seed: u64) -> Self {
        let mut hash_seeds = Vec::with_capacity(depth);
        for i in 0..depth {
            hash_seeds.push((seed as u32).wrapping_add(i as u32));
        }
        Self {
            depth,
            width,
            counters: vec![vec![0; width]; depth],
            hash_seeds,
            hh_candidates: HashSet::new(),
            cumul_l2: u32::MAX - 1,
            cumul_l3: u32::MAX - 2, 
        }
    }

    pub fn insert(&mut self, item: &[u8], count: u32) {
        let mut hash_index = vec![0; self.depth];
        let mut ret_val = vec![0; self.depth];
        let mut hh_flag = true;

        for d in 0..self.depth {
            hash_index[d] = self.hash(item, self.hash_seeds[d]) % self.width;
        }

        for d in 0..self.depth {
            ret_val[d] = self.increment_counter(d, hash_index[d], count);
            if ret_val[d] <= 10000 {
                hh_flag = false;
            }
        }

        if hh_flag {
            if let Ok(item_u32) = item.try_into().map(u32::from_ne_bytes) {
                self.hh_candidates.insert(item_u32);
            }
        }
    }

    pub fn query(&self, item: &[u8]) -> u32 {
        let mut hash_index = vec![0; self.depth];
        let mut ret_val = vec![0; self.depth];
        let mut count_query = u32::MAX;

        for d in 0..self.depth {
            hash_index[d] = self.hash(item, self.hash_seeds[d]) % self.width;
        }

        for d in 0..self.depth {
            ret_val[d] = self.query_counter(d, hash_index[d]);
            count_query = count_query.min(ret_val[d]);
        }

        count_query
    }

    pub fn get_cardinality(&self) -> i32 {
        let mut avgnum_empty_counter = 0;
        for d in 0..self.depth {
            avgnum_empty_counter += self.counters[d].iter().filter(|&&x| x == 0).count();
        }
        (self.width as f64 * (self.width as f64 / avgnum_empty_counter as f64).ln()) as i32
    }

    fn increment_counter(&mut self, depth: usize, index: usize, count: u32) -> u32 {
        let old_val = self.counters[depth][index];
        let new_val = old_val.saturating_add(count);
        self.counters[depth][index] = new_val;
        new_val
    }

    fn query_counter(&self, depth: usize, index: usize) -> u32 {
        self.counters[depth][index]
    }

    fn hash(&self, item: &[u8], seed: u32) -> usize {
        let mut hash = seed;
        for &byte in item {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
        }
        hash as usize
    }
}