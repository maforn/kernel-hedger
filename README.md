# Transparent Request Hedging with eBPF

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![Language](https://img.shields.io/badge/language-C%20%7C%20Python-blue)

## Abstract
This repository contains the source code and benchmarking suite for my Collegio Superiore's Short Thesis: **"Kernel-level Hedged Requests via eBPF"**

This project demonstrates how moving reliability logic (Request Hedging) from User Space (Application) to Kernel Space (eBPF) eliminates **User Space Jitter** (caused by Garbage Collection and Process Scheduling), resulting in a 96% reduction in P99 latency.

## Key Features
* **Oblvious Client:** No changes required to the application code. The eBPF program attaches to the network interface (`lo`) transparently.
* **Kernel Precision:** Hedging timers run in kernel context (SoftIRQ), immune to Python/Java GC pauses.
* **Deterministic Benchmarking:** Includes a custom UDP server with "Deterministic Chaos" fault injection to scientifically compare algorithms.
* **Smart Networking:** Solves low-level challenges like **Checksum Offloading** and **Martian Packet** routing.

## Results

| Method | P99 Latency | Max Latency (Jitter) |
| :--- | :--- | :--- |
| **Baseline** | 401.14 ms | 401.60 ms |
| **App-Hedged (Python)** | 13.08 ms | **22.09 ms** (High Jitter) |
| **Kernel-Hedged (eBPF)** | 12.83 ms | **13.35 ms** (Stable) |

*The Kernel implementation is only slighly better than the Application P99 but eliminates the 9ms+ jitter spike caused by user-space scheduling.*

## Architecture
1.  **Splitter (TC Egress):** Intercepts and clones outgoing UDP packets.
2.  **Delay Line:** Uses `veth` pairs + `netem` to buffer packets in the kernel.
3.  **Rescuer (TC Ingress):** Checks the shared BPF Map (`scoreboard`). If the original request hasn't received an ACK, it modifies and re-injects the cloned packet.

## Installation & Usage

### Prerequisites
* Linux Kernel 5.x+ (Headers installed)
* `bcc` (BPF Compiler Collection)
* `ethtool` (To disable checksum offloading)

### Running the Experiment
1.  **Start the Deterministic Server:**
    ```bash
    python3 server_dual.py
    ```
2.  **Load the eBPF Program:**
    ```bash
    sudo python3 ebpf_final_hedge.py
    ```
3.  **Run the Benchmark:**
    ```bash
    python3 benchmark_suite.py
    ```

## Repository Structure
* `/src`: C (eBPF) and Python source code.
* `/thesis`: LaTeX source code for the Master's Thesis document.

## Citation
If you use this code, please cite:
> Matteo Fornaini, "Kernel-level Hedged Requests via eBPF", Final's Thesis, Collegio Superiore dell'Università di Bologna, 2026.
