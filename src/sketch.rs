use std::collections::HashSet;
use std::convert::TryInto;

pub struct CMSketch {
    depth: usize,
    width: usize,
    counters: Vec<Vec<i32>>,
    hash_seeds: Vec<u32>,
    hh_candidates: HashSet<Vec<u8>>,
}

impl CMSketch {
    pub fn new(memory_in_bytes: usize, depth: usize, seed: u64) -> Self {
        let width = memory_in_bytes / 4 / depth;
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
        }
    }

    pub fn insert(&mut self, item: &[u8], count: i32) {
        let mut meta_indicator = vec![0; self.depth];
        for i in 0..self.depth {
            let index = self.hash(item, self.hash_seeds[i]) % self.width;
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
            let index = self.hash(item, self.hash_seeds[i]) % self.width;
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

    fn hash(&self, item: &[u8], seed: u32) -> usize {
        let mut hash = seed;
        for &byte in item {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
        }
        hash as usize
    }
}

pub struct FCMSketch {
    depth: usize,
    width: usize,
    counters: Vec<Vec<u32>>,
    hash_seeds: Vec<u32>,
    hh_candidates: HashSet<u32>,
    cumul_l2: u32,
    cumul_l3: u32,
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

pub enum Sketch {
    CMSketch(CMSketch),
    FCMSketch(FCMSketch),
}

impl Sketch {
    pub fn new_cm_sketch(memory_in_bytes: usize, depth: usize, seed: u64) -> Self {
        Sketch::CMSketch(CMSketch::new(memory_in_bytes, depth, seed))
    }

    pub fn new_fcm_sketch(depth: usize, width: usize, seed: u64) -> Self {
        Sketch::FCMSketch(FCMSketch::new(depth, width, seed))
    }

    pub fn increment(&mut self, item: &str, count: u64) {
        match self {
            Sketch::CMSketch(sketch) => sketch.insert(item.as_bytes(), count as i32),
            Sketch::FCMSketch(sketch) => sketch.insert(item.as_bytes(), count as u32),
        }
    }

    pub fn estimate(&self, item: &str) -> u64 {
        match self {
            Sketch::CMSketch(sketch) => sketch.query(item.as_bytes()) as u64,
            Sketch::FCMSketch(sketch) => sketch.query(item.as_bytes()) as u64,
        }
    }

    pub fn clear(&mut self) {
        match self {
            Sketch::CMSketch(sketch) => sketch.counters.iter_mut().for_each(|row| row.fill(0)),
            Sketch::FCMSketch(sketch) => sketch.counters.iter_mut().for_each(|row| row.fill(0)),
        }
    }
}