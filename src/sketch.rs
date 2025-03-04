pub struct CountMinSketch {
    width: usize,
    depth: usize,
    table: Vec<Vec<u64>>,
    seed: u64,
}

impl CountMinSketch {
    pub fn new(width: usize, depth: usize, seed: u64) -> Self {
        Self {
            width,
            depth,
            table: vec![vec![0; width]; depth],
            seed,
        }
    }

    pub fn increment(&mut self, item: &str, count: u64) {
        // Simplified hashing for demonstration purposes
        let hash = self.hash(item);
        for i in 0..self.depth {
            let index = (hash + i as u64) as usize % self.width;
            self.table[i][index] += count;
        }
    }

    pub fn estimate(&self, item: &str) -> u64 {
        // Simplified hashing for demonstration purposes
        let hash = self.hash(item);
        (0..self.depth)
            .map(|i| self.table[i][(hash + i as u64) as usize % self.width])
            .min()
            .unwrap_or(0)
    }

    pub fn clear(&mut self) {
        for row in &mut self.table {
            row.fill(0);
        }
    }

    fn hash(&self, item: &str) -> u64 {
        // Simplified hashing for demonstration purposes
        let mut hash = self.seed;
        for byte in item.bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        }
        hash
    }
}

pub enum Sketch {
    CountMinSketch(CountMinSketch),
}

impl Sketch {
    pub fn new_count_min_sketch(width: usize, depth: usize, seed: u64) -> Self {
        Sketch::CountMinSketch(CountMinSketch::new(width, depth, seed))
    }

    pub fn increment(&mut self, item: &str, count: u64) {
        match self {
            Sketch::CountMinSketch(sketch) => sketch.increment(item, count),
        }
    }

    pub fn estimate(&self, item: &str) -> u64 {
        match self {
            Sketch::CountMinSketch(sketch) => sketch.estimate(item),
        }
    }

    pub fn clear(&mut self) {
        match self {
            Sketch::CountMinSketch(sketch) => sketch.clear(),
        }
    }
}