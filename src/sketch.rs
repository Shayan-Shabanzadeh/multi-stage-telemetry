use crate::cm_sketch::CMSketch;
use crate::fcm_sketch::FCMSketch;
use crate::elastic_sketch::ElasticSketch;
use crate::deterministic_sketch::DeterministicSketch;

#[derive(Clone)]
pub enum Sketch {
    CMSketch(CMSketch),
    FCMSketch(FCMSketch),
    ElasticSketch(ElasticSketch),
    DeterministicSketch(DeterministicSketch),
}

impl Sketch {
    pub fn new_cm_sketch(memory_in_bytes: usize, depth: usize, seed: u64) -> Self {
        Sketch::CMSketch(CMSketch::new(memory_in_bytes, depth, seed))
    }

    pub fn new_fcm_sketch(depth: usize, width: usize, seed: u64) -> Self {
        Sketch::FCMSketch(FCMSketch::new(depth, width, seed))
    }

    pub fn new_elastic_sketch(depth: usize, width: usize, seed: u64) -> Self {
        Sketch::ElasticSketch(ElasticSketch::new(depth, width, seed))
    }

    pub fn new_deterministic_sketch() -> Self {
        Sketch::DeterministicSketch(DeterministicSketch::new())
    }

    pub fn increment(&mut self, item: &str, count: u64) {
        match self {
            Sketch::CMSketch(sketch) => sketch.insert(item.as_bytes(), count as i32),
            Sketch::FCMSketch(sketch) => sketch.insert(item.as_bytes(), count as u32),
            Sketch::ElasticSketch(sketch) => sketch.insert(item.as_bytes(), count as u32),
            Sketch::DeterministicSketch(sketch) => sketch.insert(item, count),
        }
    }

    pub fn estimate(&self, item: &str) -> u64 {
        match self {
            Sketch::CMSketch(sketch) => sketch.query(item.as_bytes()) as u64,
            Sketch::FCMSketch(sketch) => sketch.query(item.as_bytes()) as u64,
            Sketch::ElasticSketch(sketch) => sketch.query(item.as_bytes()) as u64,
            Sketch::DeterministicSketch(sketch) => sketch.query(item),
        }
    }

    pub fn clear(&mut self) {
        match self {
            Sketch::CMSketch(sketch) => sketch.counters.iter_mut().for_each(|row| row.fill(0)),
            Sketch::FCMSketch(sketch) => sketch.counters.iter_mut().for_each(|row| row.fill(0)),
            Sketch::ElasticSketch(sketch) => {
                sketch.light_counters.iter_mut().for_each(|row| row.fill(0));
                sketch.heavy_counters.fill(0);
            }
            Sketch::DeterministicSketch(sketch) => sketch.clear(),
        }
    }
}