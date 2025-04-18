#!/bin/bash

# Build the project in release mode
cargo build --release

# Check if the build was successful
if [ $? -eq 0 ]; then
    echo "Build successful. Running the project..."
    # Run the project with the specified arguments
    cargo run --release -- /home/shayansh/mawilab/08-12-2024/202408121400.pcap 5 40 5
    # cargo run --release -- /home/shayansh/mawilab/10-02-2023/202302101400.pcap 10 5  1
    # cargo run --release -- /home/shayansh/mawilab/11-19-2024/202411191400.pcap 10 5  1
    # cargo run --release -- /home/shayansh/mawilab/11-19-2024/202411191400.pcap 10 5  1


else 
    echo "Build failed. Please check the error messages above."
fi