#!/bin/bash

# Build the project in release mode
cargo build --release

# Check if the build was successful
if [ $? -eq 0 ]; then
    echo "Build successful. Running the project..."
    cargo run --release -- /home/shayansh/mawilab/2024-08-12/202408121400.pcap 30 60000 5
else 
    echo "Build failed. Please check the error messages above."
fi