use std::collections::HashSet;
use crate::bobhash32::BOBHash32;

pub struct CMSketch {
    pub depth: usize,
    pub width: usize,
    pub counters: Vec<Vec<i32>>,
    pub hash_seeds: Vec<BOBHash32>,
    pub hh_candidates: HashSet<Vec<u8>>,
}

impl CMSketch {
    pub fn new(memory_in_bytes: usize, depth: usize, seed: u64) -> Self {
        let width = memory_in_bytes / 4 / depth;
        let mut hash_seeds = Vec::with_capacity(depth);
        for i in 0..depth {
            let prime_index = BOBHash32::get_random_prime_index();
            hash_seeds.push(BOBHash32::new(prime_index));
        }
        Self {
            depth,
            width,
            counters: vec![vec![0; width]; depth],
            hash_seeds,
            hh_candidates: HashSet::new(),
        }
    }

    pub fn insert(&mut self, item: &[u8], count: i32) {
        let mut meta_indicator = vec![0; self.depth];
        for i in 0..self.depth {
            let index = self.hash_seeds[i].run(item) as usize % self.width;
            self.counters[i][index] += count;
            if self.counters[i][index] > 10000 {
                meta_indicator[i] = 1;
            }
        }
        if meta_indicator.iter().sum::<i32>() == self.depth as i32 {
            self.heavy_insert(item);
        }
    }

    pub fn query(&self, item: &[u8]) -> i32 {
        let mut result = i32::MAX;
        for i in 0..self.depth {
            let index = self.hash_seeds[i].run(item) as usize % self.width;
            result = result.min(self.counters[i][index]);
        }
        result
    }

    pub fn get_cardinality(&self) -> i32 {
        let empty = self.counters[0].iter().filter(|&&x| x == 0).count();
        (self.width as f64 * (self.width as f64 / empty as f64).ln()) as i32
    }

    fn heavy_insert(&mut self, item: &[u8]) {
        self.hh_candidates.insert(item.to_vec());
    }
}