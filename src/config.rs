use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
pub struct Config {
    pub seed: u64,
}

pub fn read_config(file_path: &str) -> Config {
    let config_data = fs::read_to_string(file_path).expect("Unable to read config file");
    serde_json::from_str(&config_data).expect("Unable to parse config file")
}