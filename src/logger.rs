use std::fs::OpenOptions;
use std::io::Write;
use std::collections::BTreeMap;
use crate::count_min_sketch::CountMinSketch;

pub struct Logger {
    log_file: std::fs::File,
}

impl Logger {
    pub fn new(log_file_path: &str) -> Self {
        let log_file = OpenOptions::new().write(true).create(true).truncate(true).open(log_file_path).expect("Cannot open log file");
        Self { log_file }
    }

    pub fn log_epoch_results(&mut self, sketch: &CountMinSketch, ground_truth: &BTreeMap<String, usize>, total_packets: usize, threshold: usize) {
        println!("\n========================= EPOCH RESULTS =========================");
        let mut log_output = String::new();
        let mut epoch_total_are = 0.0;
        let mut epoch_valid_entries = 0;

        for (d_ip, true_count) in ground_truth {
            if *true_count > threshold {
                let estimated_count = sketch.estimate(d_ip);
                let re = ((estimated_count as f64 - *true_count as f64).abs()) / (*true_count as f64);
                epoch_total_are += re;
                epoch_valid_entries += 1;

                let output = format!("New TCP connections detected: {} -> True: {}, Estimated: {}, RE: {:.4}", d_ip, true_count, estimated_count, re);
                println!("{}", output);
                log_output.push_str(&format!("{}\n", output));
            }
        }

        let avg_are = if epoch_valid_entries > 0 {
            epoch_total_are / epoch_valid_entries as f64
        } else {
            0.0
        };
        let are_output = format!("Average ARE for epoch: {:.4}", avg_are);
        let packet_output = format!("Total packets processed in epoch: {}", total_packets);
        let valid_entries_output = format!("Valid entries counted: {}", epoch_valid_entries);
        println!("{}", are_output);
        println!("{}", packet_output);
        println!("{}", valid_entries_output);
        log_output.push_str(&format!("{}\n{}\n{}\n", are_output, packet_output, valid_entries_output));

        self.log_file.write_all(log_output.as_bytes()).expect("Failed to write to log file");
    }
}