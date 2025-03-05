use crate::cm_sketch::CMSketch;
use crate::fcm_sketch::FCMSketch;

pub enum Sketch {
    CMSketch(CMSketch),
    FCMSketch(FCMSketch),
}

impl Sketch {
    pub fn new_cm_sketch(memory_in_bytes: usize, depth: usize, seed: u64) -> Self {
        Sketch::CMSketch(CMSketch::new(memory_in_bytes, depth, seed))
    }

    pub fn new_fcm_sketch(depth: usize, width: usize, seed: u64) -> Self {
        Sketch::FCMSketch(FCMSketch::new(depth, width, seed))
    }

    pub fn increment(&mut self, item: &str, count: u64) {
        match self {
            Sketch::CMSketch(sketch) => sketch.insert(item.as_bytes(), count as i32),
            Sketch::FCMSketch(sketch) => sketch.insert(item.as_bytes(), count as u32),
        }
    }

    pub fn estimate(&self, item: &str) -> u64 {
        match self {
            Sketch::CMSketch(sketch) => sketch.query(item.as_bytes()) as u64,
            Sketch::FCMSketch(sketch) => sketch.query(item.as_bytes()) as u64,
        }
    }

    pub fn clear(&mut self) {
        match self {
            Sketch::CMSketch(sketch) => sketch.counters.iter_mut().for_each(|row| row.fill(0)),
            Sketch::FCMSketch(sketch) => sketch.counters.iter_mut().for_each(|row| row.fill(0)),
        }
    }
}