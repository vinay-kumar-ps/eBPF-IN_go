# eBPF Traffic Filter

This repository contains an eBPF program that filters network traffic based on a specific TCP port and a process name. It allows traffic only at a specific TCP port (default 4040) for a given process name (e.g., "myprocess"). All the traffic to all other ports for that process will be dropped.

## Features

- Filter network traffic based on a specified TCP port.
- Allow traffic only for a specified process name.
- Drop all other traffic for that process on different ports.
- Uses XDP (eXpress Data Path) for high-performance packet processing.

## Requirements

- Linux kernel version 5.0 or higher.
- Go 1.13 or higher.
- C compiler (e.g., `gcc`).
- `clang` and `llvm` for compiling the eBPF program.
- `iproute2` package for managing network interfaces.

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/ebpf-traffic-filter.git
   cd ebpf-traffic-filter
