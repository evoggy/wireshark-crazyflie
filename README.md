# Wireshark Crazyflie

Wireshark extcap and dissector for capturing and analyzing Crazyflie CRTP protocol traffic.

## Overview

This project provides tools to capture CRTP (Crazy RealTime Protocol) packets from Crazyflie applications directly in Wireshark:

- **crazyflie-extcap**: A Wireshark extcap plugin that receives packets from Crazyflie applications
- **crtp-dissector.lua**: A Lua dissector that decodes CRTP packets in Wireshark

## Requirements

- Wireshark 3.0+
- Rust toolchain (for building)
- A Crazyflie application built with the `wireshark` feature enabled

## Installation

### Build the extcap

```bash
cargo build --release
```

### Install the extcap and dissector

Create symlinks to the Wireshark plugin directories:

```bash
# Create directories if they don't exist
mkdir -p ~/.local/lib/wireshark/extcap
mkdir -p ~/.local/lib/wireshark/plugins

# Symlink the extcap binary
ln -s "$(pwd)/target/release/crazyflie-extcap" ~/.local/lib/wireshark/extcap/

# Symlink the dissector
ln -s "$(pwd)/dissector/crtp-dissector.lua" ~/.local/lib/wireshark/plugins/
```

## Usage

1. **Start Wireshark** and select the "Crazyflie CRTP" interface
2. **Click Start** to begin capturing
3. **Run your Crazyflie application** (must be built with `wireshark` feature)
4. Packets will appear in Wireshark as they are sent/received

## Building applications with capture support

To enable packet capture in your application, build with the `packet_capture` feature:

```bash
# For crazyflie-link based applications
cargo build --features packet_capture
```

The application must call `crazyflie_link::capture::init()` before establishing connections.

## How it works

```text
┌─────────────────┐     Unix Socket      ┌──────────────────┐     FIFO     ┌───────────┐
│  Your App       │ ──────────────────── │ crazyflie-extcap │ ──────────── │ Wireshark │
│ (crazyflie-link)│   /tmp/crazyflie-    │                  │    PCAP      │           │
│                 │   wireshark.sock     │                  │   packets    │           │
└─────────────────┘                      └──────────────────┘              └───────────┘
```

1. When Wireshark starts capturing on the "Crazyflie CRTP" interface, it launches the extcap
2. The extcap creates a Unix socket at `/tmp/crazyflie-wireshark.sock`
3. Your application (with `wireshark` feature) connects to this socket
4. Packets are forwarded from your app → extcap → Wireshark
5. The Lua dissector decodes the CRTP protocol fields

## Packet format

The dissector displays:

- **Link type**: Radio (Crazyradio) or USB
- **Direction**: TX (to Crazyflie) or RX (from Crazyflie)
- **Address**: Radio address (5 bytes) or USB serial
- **Channel**: Radio channel (0-125)
- **CRTP Port/Channel**: Protocol port and channel
- **Payload**: Decoded based on port (Console, Parameters, Log, etc.)

## License

MIT OR Apache-2.0
