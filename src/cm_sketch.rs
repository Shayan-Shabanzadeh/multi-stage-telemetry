use crate::bobhash32::BOBHash32;

pub struct CMSketch {
    pub depth: usize,
    pub width: usize,
    pub counters: Vec<Vec<i32>>,
    pub hashes: Vec<BOBHash32>,
}

impl CMSketch {
    pub fn new(memory_in_bytes: usize, depth: usize , _seed: u64) -> Self {
        let width = memory_in_bytes / 4 / depth;
        
        let counters = vec![vec![0; width]; depth];

        let hashes: Vec<BOBHash32> = (0..depth)
            .map(|i| BOBHash32::new(750 + (i as u32)))
            .collect();

        Self {
            depth,
            width,
            counters,
            hashes,
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

    // pub fn clear(&mut self) {
    //     for counters_row in &mut self.counters {
    //         counters_row.fill(0);
    //     }
    // }
}
