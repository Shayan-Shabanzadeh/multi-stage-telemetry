#!/bin/bash

# Build the project in release mode
cargo build --release

# Check if the build was successful
if [ $? -eq 0 ]; then
    echo "Build successful. Running the project..."
    # Run the project with the specified arguments
    cargo run --release -- ~/mawilab/08-12-2024/202408121400.pcap 10 100 3
else 
    echo "Build failed. Please check the error messages above."
fi