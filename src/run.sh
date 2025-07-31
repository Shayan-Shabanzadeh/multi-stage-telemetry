    #!/bin/bash

    # Build the project in release mode
    cargo build --release

# Check if the build was successful
if [ $? -eq 0 ]; then
    echo "Build successful. Running the project..."
    cargo run --release -- /home/shayansh/mawilab/2023-02-10/202302101400.pcap 30 40 1
    # cargo run --release -- /home/shayansh/mawilab/2024-11-19/202411191400.pcap 30 1 1

    # cargo run --release -- /home/shayansh/mawilab/2024-11-19/202411191400.pcap 30 1000000 5
    # cargo run --release -- /home/shayansh/mawilab/2024-11-19/202411191400.pcap 30 1 5



else 
    echo "Build failed. Please check the error messages above."
fi