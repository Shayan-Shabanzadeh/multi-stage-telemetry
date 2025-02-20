# Packet Processing with Dynamic Query Execution

This project implements a packet processing system that supports stream processing with dynamic query execution. It processes packets from a PCAP file, applying filter, map, and reduce operations in sequence according to a user-defined query plan.

## Features

- **PacketInfo**: Represents packet data with source IP, destination IP, source port, destination port, and TCP flags.
- **QueryPlan**: Defines the query plan with operations such as filter, map, reduce, and filter result.
- **Dynamic Query Execution**: Processes packets according to the query plan, applying operations in sequence.

## Prerequisites

- Rust (https://www.rust-lang.org/tools/install)
- PCAP file for testing

## Building the Project

1. Clone the repository:
    ```sh
    git clone <repository-url>
    cd <repository-directory>
    ```

2. Ensure you are on the `main` branch:
    ```sh
    git checkout main
    ```

3. Build the project in release mode:
    ```sh
    cargo build --release
    ```

## Running the Project

To run the project, use the following command:

```sh
cargo run --release -- <pcap_file> <epoch_size_seconds> <threshold>