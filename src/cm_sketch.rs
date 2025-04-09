use std::collections::HashSet;
use crate::bobhash32::BOBHash32;

pub const HH_THRESHOLD: i32 = 10000; // Matches the C++ definition exactly

pub struct CMSketch {
    pub depth: usize,
    pub width: usize,
    pub counters: Vec<Vec<i32>>,
    pub hashes: Vec<BOBHash32>,
    pub hh_candidates: HashSet<Vec<u8>>,
    pub memory_in_bytes: usize,
    pub name: String,
}

impl CMSketch {
    pub fn new(memory_in_bytes: usize, depth: usize, seed: u64) -> Self {
        let width = memory_in_bytes / 4 / depth;

        let counters = vec![vec![0; width]; depth];

        // Initialize hash functions using BOBHash32 with offsets starting from 750 + seed
        let hashes: Vec<BOBHash32> = (0..depth)
            .map(|i| BOBHash32::new((seed as u32) + 750 + (i as u32)))
            .collect();

        let name = format!("CM@{}@{}", memory_in_bytes, depth);

        Self {
            depth,
            width,
            counters,
            hashes,
            hh_candidates: HashSet::new(),
            memory_in_bytes,
            name,
        }
    }

    pub fn insert(&mut self, key: &[u8], count: i32) {
        let mut meta_indicator = vec![0; self.depth];

        for i in 0..self.depth {
            let index = (self.hashes[i].run(key) as usize) % self.width;
            self.counters[i][index] += count;
            if self.counters[i][index] > HH_THRESHOLD {
                meta_indicator[i] = 1;
            }
        }

        if meta_indicator.iter().sum::<i32>() == self.depth as i32 {
            self.heavy_insert(key);
        }
    }

    pub fn query(&self, key: &[u8]) -> i32 {
        let mut ret = i32::MAX;
        for i in 0..self.depth {
            let index = (self.hashes[i].run(key) as usize) % self.width;
            ret = ret.min(self.counters[i][index]);
        }
        ret
    }

    pub fn get_cardinality(&self) -> i32 {
        let empty = self.counters[0].iter().filter(|&&x| x == 0).count();
        if empty == 0 {
            return self.width as i32;
        }
        (self.width as f64 * (self.width as f64 / empty as f64).ln()) as i32
    }

    fn heavy_insert(&mut self, key: &[u8]) {
        self.hh_candidates.insert(key.to_vec());
    }

    pub fn print_basic_info(&self) {
        println!("CM Sketch");
        println!("\tCounters per depth: {}", self.width);
        println!("\tMemory: {:.6} MB", (self.width * self.depth * 4) as f64 / 1024.0 / 1024.0);
        let mut total_packets = 0;
        for dep in 0..self.depth {
            total_packets += self.counters[dep].iter().sum::<i32>();
        }
        println!("\tTotal packets at depth {}: {}", self.depth, total_packets);
    }

    pub fn clear(&mut self) {
        for dep in 0..self.depth {
            self.counters[dep].fill(0);
        }
        self.hh_candidates.clear();
    }
}