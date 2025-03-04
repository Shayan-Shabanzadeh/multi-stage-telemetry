use std::collections::HashSet;

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
    width: usize,
    depth: usize,
    table: Vec<Vec<u64>>,
    seed: u64,
}

impl FCMSketch {
    pub fn new(width: usize, depth: usize, seed: u64) -> Self {
        Self {
            width,
            depth,
            table: vec![vec![0; width]; depth],
            seed,
        }
    }

    pub fn insert(&mut self, item: &[u8], count: u64) {
        let hash = self.hash(item);
        for i in 0..self.depth {
            let index = (hash + i as u64) as usize % self.width;
            self.table[i][index] += count;
        }
    }

    pub fn query(&self, item: &[u8]) -> u64 {
        let hash = self.hash(item);
        (0..self.depth)
            .map(|i| self.table[i][(hash + i as u64) as usize % self.width])
            .min()
            .unwrap_or(0)
    }

    pub fn clear(&mut self) {
        for row in &mut self.table {
            row.fill(0);
        }
    }

    fn hash(&self, item: &[u8]) -> u64 {
        let mut hash = self.seed;
        for &byte in item {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        }
        hash
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

    pub fn new_fcm_sketch(width: usize, depth: usize, seed: u64) -> Self {
        Sketch::FCMSketch(FCMSketch::new(width, depth, seed))
    }

    pub fn increment(&mut self, item: &str, count: u64) {
        match self {
            Sketch::CMSketch(sketch) => sketch.insert(item.as_bytes(), count as i32),
            Sketch::FCMSketch(sketch) => sketch.insert(item.as_bytes(), count),
        }
    }

    pub fn estimate(&self, item: &str) -> u64 {
        match self {
            Sketch::CMSketch(sketch) => sketch.query(item.as_bytes()) as u64,
            Sketch::FCMSketch(sketch) => sketch.query(item.as_bytes()),
        }
    }

    pub fn clear(&mut self) {
        match self {
            Sketch::CMSketch(sketch) => sketch.counters.iter_mut().for_each(|row| row.fill(0)),
            Sketch::FCMSketch(sketch) => sketch.clear(),
        }
    }
}