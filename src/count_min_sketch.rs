use std::collections::HashMap;
use twox_hash::XxHash64;
use std::hash::Hasher;

#[derive(Debug)]
pub struct CountMinSketch {
    width: usize,
    depth: usize,
    table: Vec<Vec<u64>>,
    keys: HashMap<String, usize>,
    seed: u64, // Add a seed field
}

impl CountMinSketch {
    pub fn new(width: usize, depth: usize, seed: u64) -> Self {
        Self {
            width,
            depth,
            table: vec![vec![0; width]; depth],
            keys: HashMap::new(),
            seed, // Initialize the seed
        }
    }

    fn hash(&self, item: &str, i: u32) -> usize {
        let mut hasher = XxHash64::with_seed(self.seed + i as u64); // Use the seed
        hasher.write(item.as_bytes());
        (hasher.finish() as usize) % self.width
    }

    pub fn increment(&mut self, item: &str, count: u64) {
        for i in 0..self.depth {
            let index = self.hash(item, i as u32);
            self.table[i][index] += count;
        }
        *self.keys.entry(item.to_string()).or_insert(0) += count as usize;
    }

    pub fn estimate(&self, item: &str) -> u64 {
        (0..self.depth)
            .map(|i| self.table[i][self.hash(item, i as u32)])
            .min()
            .unwrap_or(0)
    }

    pub fn clear(&mut self) { // Change to mutable reference
        for row in &mut self.table {
            row.fill(0);
        }
        self.keys.clear();
    }
}