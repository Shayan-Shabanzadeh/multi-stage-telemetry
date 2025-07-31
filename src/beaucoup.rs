use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use bitvec::prelude::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub struct BeauCoupSketch {
    num_rows: usize,          // m
    num_coupons: usize,       // w
    d: usize,                 // number of hash functions
    max_coupons_per_packet: usize,
    tables: Vec<BitVec>,
    rng: StdRng,
    hash_seeds: Vec<u64>,
}

impl BeauCoupSketch {
    pub fn new(num_rows: usize, num_coupons: usize, d: usize, max_coupons_per_packet: usize, seed: u64) -> Self {
        let tables = vec![bitvec![0; num_coupons]; num_rows];
        let rng = StdRng::seed_from_u64(seed);
        let hash_seeds = (0..d).map(|i| seed.wrapping_add(i as u64)).collect();

        Self {
            num_rows,
            num_coupons,
            d,
            max_coupons_per_packet,
            tables,
            rng,
            hash_seeds,
        }
    }

    fn hash(&self, key: &str, seed: u64) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        seed.hash(&mut hasher);
        (hasher.finish() as usize) % self.num_rows
    }

    pub fn insert(&mut self, key: &str) {
        for i in 0..self.d {
            let row_index = self.hash(key, self.hash_seeds[i]);
            let bv = &mut self.tables[row_index];

            for _ in 0..self.max_coupons_per_packet {
                let coupon = self.rng.gen_range(0..self.num_coupons);
                bv.set(coupon, true);
            }
        }
    }

    pub fn estimate(&self, key: &str) -> u64 {
        let mut max_k = 0;

        for i in 0..self.d {
            let row_index = self.hash(key, self.hash_seeds[i]);
            let bv = &self.tables[row_index];
            let k = bv.count_ones();

            if k > max_k {
                max_k = k;
            }
        }

        if max_k == 0 || max_k as usize >= self.num_coupons {
            0
        } else {
            let n = self.num_coupons as f64;
            let k = max_k as f64;
            (n * (n / (n - k)).ln()) as u64
        }
    }

    pub fn clear(&mut self) {
        for bv in self.tables.iter_mut() {
            bv.fill(false);
        }
    }

pub fn contains(&self, key: &str) -> bool {
    for i in 0..self.d {
        let row_index = self.hash(key, self.hash_seeds[i]);
        let bv = &self.tables[row_index];

        if bv.any() {
            return true;
        }
    }
    false
}
}