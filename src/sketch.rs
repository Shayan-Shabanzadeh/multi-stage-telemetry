use crate::cm_sketch::CMSketch;
use crate::fcm_sketch::FCMSketch;
use crate::elastic_sketch::ElasticSketch;
use crate::deterministic_sketch::DeterministicSketch;
use crate::bloom_filter::BloomFilter;

pub enum Sketch {
    CMSketch(CMSketch),
    FCMSketch(FCMSketch),
    ElasticSketch(ElasticSketch),
    DeterministicSketch(DeterministicSketch),
    BloomFilter(BloomFilter),
}

impl Sketch {
    pub fn new_cm_sketch(memory_in_bytes: usize, depth: usize, seed: u64) -> Self {
        Sketch::CMSketch(CMSketch::new(memory_in_bytes, depth, seed))
    }

    pub fn new_fcm_sketch(
        depth: usize,
        width_l1: usize,
        width_l2: usize,
        width_l3: usize,
        threshold_l1: u32,
        threshold_l2: u32,
        seed: u64,
    ) -> Self {
        Sketch::FCMSketch(FCMSketch::new(
            depth, width_l1, width_l2, width_l3, threshold_l1, threshold_l2, seed,
        ))
    }

    pub fn new_elastic_sketch(depth: usize, width: usize, seed: u64) -> Self {
        Sketch::ElasticSketch(ElasticSketch::new(depth, width, seed))
    }

    pub fn new_deterministic_sketch() -> Self {
        Sketch::DeterministicSketch(DeterministicSketch::new())
    }

    pub fn new_bloom_filter(expected_items: usize, false_positive_rate: f64) -> Self {
        Sketch::BloomFilter(BloomFilter::new(expected_items, false_positive_rate))
    }

    pub fn contains(&self, item: &str) -> bool {
        match self {
            Sketch::CMSketch(_) => panic!("CMSketch does not support contains"),
            Sketch::FCMSketch(_) => panic!("FCMSketch does not support contains"),
            Sketch::ElasticSketch(_) => panic!("ElasticSketch does not support contains"),
            Sketch::DeterministicSketch(_) => panic!("DeterministicSketch does not support contains"),
            Sketch::BloomFilter(bloom) => bloom.contains(item),
        }
    }

    pub fn increment(&mut self, item: &str, count: u64) {
        match self {
            Sketch::CMSketch(sketch) => sketch.insert(item.as_bytes(), count as i32),
            Sketch::FCMSketch(sketch) => sketch.insert(item.as_bytes(), count as u32),
            Sketch::ElasticSketch(sketch) => sketch.insert(item.as_bytes(), count as u32),
            Sketch::DeterministicSketch(sketch) => sketch.insert(item, count),
            Sketch::BloomFilter(_) => panic!("BloomFilter does not support increment operation"),
        }
    }

    pub fn estimate(&self, item: &str) -> u64 {
        match self {
            Sketch::CMSketch(sketch) => sketch.query(item.as_bytes()) as u64,
            Sketch::FCMSketch(sketch) => sketch.query(item.as_bytes()) as u64,
            Sketch::ElasticSketch(sketch) => sketch.query(item.as_bytes()) as u64,
            Sketch::DeterministicSketch(sketch) => sketch.query(item),
            Sketch::BloomFilter(_) => panic!("BloomFilter does not support estimate operation"),
        }
    }

    pub fn insert(&mut self, item: &str) {
        match self {
            Sketch::CMSketch(_) => panic!("CMSketch does not support insert"),
            Sketch::FCMSketch(_) => panic!("FCMSketch does not support insert"),
            Sketch::ElasticSketch(_) => panic!("ElasticSketch does not support insert"),
            Sketch::DeterministicSketch(_) => panic!("DeterministicSketch does not support insert"),
            Sketch::BloomFilter(bloom) => bloom.insert(item),
        }
    }

    pub fn clear(&mut self) {
        match self {
            Sketch::CMSketch(sketch) => sketch.counters.iter_mut().for_each(|row| row.fill(0)),
            Sketch::FCMSketch(sketch) => {
                sketch.counters_l1.iter_mut().for_each(|row| row.fill(0));
                sketch.counters_l2.iter_mut().for_each(|row| row.fill(0));
                sketch.counters_l3.iter_mut().for_each(|row| row.fill(0));
            }
            Sketch::ElasticSketch(sketch) => {
                sketch.light_counters.iter_mut().for_each(|row| row.fill(0));
                sketch.heavy_counters.fill(0);
            }
            Sketch::DeterministicSketch(sketch) => sketch.clear(),
            Sketch::BloomFilter(bloom) => bloom.clear(),
        }
    }
}

