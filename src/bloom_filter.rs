use bloomfilter::Bloom;

pub struct BloomFilter {
    bloom: Bloom<String>,
}

impl BloomFilter {
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        BloomFilter {
            bloom: Bloom::new_for_fp_rate(expected_items, false_positive_rate),
        }
    }

    pub fn contains(&self, item: &str) -> bool {
        self.bloom.check(&item.to_string())
    }

    pub fn insert(&mut self, item: &str) {
        self.bloom.set(&item.to_string())
    }

    pub fn clear(&mut self) {
        self.bloom.clear();
    }
}