use std::collections::HashMap;

#[derive(Clone)]
pub struct DeterministicSketch {
    counts: HashMap<String, u64>,
}

impl DeterministicSketch {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    pub fn insert(&mut self, item: &str, count: u64) {
        *self.counts.entry(item.to_string()).or_insert(0) += count;
    }

    pub fn query(&self, item: &str) -> u64 {
        *self.counts.get(item).unwrap_or(&0)
    }

    pub fn clear(&mut self) {
        self.counts.clear();
    }
}