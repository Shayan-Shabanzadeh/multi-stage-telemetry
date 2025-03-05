use crate::bobhash32::BOBHash32;
use crate::param::*;
use std::mem::size_of;

pub struct LightPart<const INIT_MEM_IN_BYTES: usize> {
    counters: [u8; INIT_MEM_IN_BYTES],
    mice_dist: [i32; 256],
    bobhash: BOBHash32,
}

impl<const INIT_MEM_IN_BYTES: usize> LightPart<INIT_MEM_IN_BYTES> {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let bobhash = BOBHash32::new(rng.gen_range(0..MAX_PRIME32 as u32));
        Self {
            counters: [0; INIT_MEM_IN_BYTES],
            mice_dist: [0; 256],
            bobhash,
        }
    }

    pub fn clear(&mut self) {
        self.counters.fill(0);
        self.mice_dist.fill(0);
    }

    pub fn insert(&mut self, key: &[u8], f: i32) {
        let hash_val = self.bobhash.run(key);
        let pos = (hash_val % INIT_MEM_IN_BYTES as u32) as usize;

        let old_val = self.counters[pos] as i32;
        let new_val = (self.counters[pos] as i32 + f).min(255);
        self.counters[pos] = new_val as u8;

        self.mice_dist[old_val as usize] -= 1;
        self.mice_dist[new_val as usize] += 1;
    }

    pub fn swap_insert(&mut self, key: &[u8], f: i32) {
        let hash_val = self.bobhash.run(key);
        let pos = (hash_val % INIT_MEM_IN_BYTES as u32) as usize;

        let f = f.min(255);
        if self.counters[pos] < f as u8 {
            let old_val = self.counters[pos] as i32;
            self.counters[pos] = f as u8;
            let new_val = self.counters[pos] as i32;

            self.mice_dist[old_val as usize] -= 1;
            self.mice_dist[new_val as usize] += 1;
        }
    }

    pub fn query(&self, key: &[u8]) -> i32 {
        let hash_val = self.bobhash.run(key);
        let pos = (hash_val % INIT_MEM_IN_BYTES as u32) as usize;
        self.counters[pos] as i32
    }

    pub fn compress(&self, ratio: usize, dst: &mut [u8]) {
        let width = self.get_compress_width(ratio);
        for i in 0..width.min(INIT_MEM_IN_BYTES) {
            let mut max_val = 0;
            for j in (i..INIT_MEM_IN_BYTES).step_by(width) {
                max_val = max_val.max(self.counters[j]);
            }
            dst[i] = max_val;
        }
    }

    pub fn query_compressed_part(&self, key: &[u8], compress_part: &[u8], compress_counter_num: usize) -> i32 {
        let hash_val = self.bobhash.run(key);
        let pos = (hash_val % INIT_MEM_IN_BYTES as u32) as usize % compress_counter_num;
        compress_part[pos] as i32
    }

    pub fn get_compress_width(&self, ratio: usize) -> usize {
        INIT_MEM_IN_BYTES / ratio
    }

    pub fn get_compress_memory(&self, ratio: usize) -> usize {
        INIT_MEM_IN_BYTES / ratio
    }

    pub fn get_memory_usage(&self) -> usize {
        INIT_MEM_IN_BYTES
    }

    pub fn get_cardinality(&self) -> i32 {
        let mice_card = self.mice_dist.iter().skip(1).sum::<i32>();
        let rate = (INIT_MEM_IN_BYTES as i32 - mice_card) as f64 / INIT_MEM_IN_BYTES as f64;
        (INIT_MEM_IN_BYTES as f64 * (1.0 / rate).ln()) as i32
    }

    pub fn get_entropy(&self) -> (i32, f64) {
        let mut tot = 0;
        let mut entr = 0.0;
        for i in 1..256 {
            tot += self.mice_dist[i] * i as i32;
            entr += self.mice_dist[i] as f64 * i as f64 * (i as f64).log2();
        }
        (tot, entr)
    }

    pub fn get_distribution(&self) -> Vec<f64> {
        let mut dist = vec![0.0; 256];
        for i in 0..256 {
            dist[i] = self.mice_dist[i] as f64;
        }
        dist
    }
}