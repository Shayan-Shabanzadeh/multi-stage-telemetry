use crate::bobhash32::BOBHash32;

pub struct BloomFilter {
    bit_vector: Vec<bool>,
    hash_functions: Vec<BOBHash32>,
    size: usize,
}

impl BloomFilter {
    pub fn new(size: usize, num_hashes: usize, seed: u64) -> Self {
        let mut hash_functions = Vec::with_capacity(num_hashes);
        for i in 0..num_hashes {
            hash_functions.push(BOBHash32::new((seed as u32) + i as u32));
        }

        BloomFilter {
            bit_vector: vec![false; size],
            hash_functions,
            size,
        }
    }

    pub fn insert(&mut self, item: &str) {
        for hash_function in &self.hash_functions {
            let index = (hash_function.run(item.as_bytes()) as usize) % self.size;
            self.bit_vector[index] = true;
        }
    }

    pub fn contains(&self, item: &str) -> bool {
        for hash_function in &self.hash_functions {
            let index = (hash_function.run(item.as_bytes()) as usize) % self.size;
            if !self.bit_vector[index] {
                return false; 
            }
        }
        true 
    }

    pub fn clear(&mut self) {
        self.bit_vector.fill(false);
    }
}