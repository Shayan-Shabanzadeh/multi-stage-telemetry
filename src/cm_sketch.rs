use crate::bobhash32::BOBHash32;

pub struct CMSketch {
    pub depth: usize,
    pub width: usize,
    pub counters: Vec<Vec<i32>>,
    pub hashes: Vec<BOBHash32>,
    pub memory_in_bytes: usize,
    pub name: String,
}

impl CMSketch {
    pub fn new(memory_in_bytes: usize, depth: usize , seed: u64) -> Self {
        let width = memory_in_bytes / 4 / depth;
        
        let counters = vec![vec![0; width]; depth];

        let hashes: Vec<BOBHash32> = (0..depth)
            .map(|i| BOBHash32::new(750 + (i as u32)))
            .collect();

        let name = format!("CM@{}@{}", memory_in_bytes, depth);

        Self {
            depth,
            width,
            counters,
            hashes,
            memory_in_bytes,
            name,
        }
    }

    pub fn insert(&mut self, key: &[u8], count: i32) {
        for i in 0..self.depth {
            let index = (self.hashes[i].run(key) as usize) % self.width;
            self.counters[i][index] += count;
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

    pub fn print_basic_info(&self) {
        println!("CM Sketch");
        println!("\tCounters: {}", self.width);
        println!("\tMemory: {:.6} MB", (self.width * 4) as f64 / 1024.0 / 1024.0);
    }

    pub fn clear(&mut self) {
        for counters_row in &mut self.counters {
            counters_row.fill(0);
        }
    }
}
