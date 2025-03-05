use rand::Rng;
use std::collections::HashSet;

const MAX_PRIME32: usize = 1229;

pub struct BOBHash32 {
    prime32_num: u32,
}

impl BOBHash32 {
    pub fn new(prime32_num: u32) -> Self {
        Self { prime32_num }
    }

    pub fn initialize(&mut self, prime32_num: u32) {
        self.prime32_num = prime32_num;
    }

    pub fn run(&self, str: &[u8]) -> u32 {
        let mut hash = self.prime32_num;
        for &byte in str {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
        }
        hash
    }

    pub fn get_random_prime_index() -> u32 {
        let mut rng = rand::thread_rng();
        rng.gen_range(0..MAX_PRIME32 as u32)
    }

    pub fn get_random_prime_index_list(n: usize) -> Vec<u32> {
        let mut rng = rand::thread_rng();
        let mut set = HashSet::new();
        while set.len() < n {
            set.insert(rng.gen_range(0..MAX_PRIME32 as u32));
        }
        set.into_iter().collect()
    }
}