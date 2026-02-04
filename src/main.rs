//! Wireshark extcap for Crazyflie CRTP protocol
//!
//! This application implements the Wireshark extcap interface to capture
//! CRTP packets from Crazyflie applications using the crazyflie-link crate
//! with the "wireshark" feature enabled.

use clap::Parser;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

/// Wireshark extcap interface name
const INTERFACE_NAME: &str = "crazyflie";
/// Wireshark extcap interface description
const INTERFACE_DESC: &str = "Crazyflie CRTP";
/// Unix socket path for receiving packets from clients
const SOCKET_PATH: &str = "/tmp/crazyflie-wireshark.sock";
/// Wireshark USER15 data link type (147)
const DLT_USER15: u32 = 162;

#[derive(Parser)]
#[command(name = "crazyflie-extcap")]
#[command(about = "Wireshark extcap for Crazyflie CRTP protocol")]
struct Args {
    /// List available interfaces
    #[arg(long)]
    extcap_interfaces: bool,

    /// List DLTs for an interface
    #[arg(long)]
    extcap_dlts: bool,

    /// Interface to use
    #[arg(long)]
    extcap_interface: Option<String>,

    /// List configuration options
    #[arg(long)]
    extcap_config: bool,

    /// Start capture
    #[arg(long)]
    capture: bool,

    /// FIFO to write packets to
    #[arg(long)]
    fifo: Option<PathBuf>,

    /// Extcap version (Wireshark passes its version here)
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    extcap_version: Option<String>,
}

fn main() {
    let args = Args::parse();

    if args.extcap_interfaces {
        print_interfaces();
    } else if args.extcap_dlts {
        print_dlts();
    } else if args.extcap_config {
        print_config();
    } else if args.capture {
        if let Some(fifo) = args.fifo {
            run_capture(&fifo);
        } else {
            eprintln!("Error: --fifo is required for capture");
            std::process::exit(1);
        }
    }
}

/// Print available extcap interfaces
fn print_interfaces() {
    println!("extcap {{version=1.0}}");
    println!(
        "interface {{value={}}}{{display={}}}",
        INTERFACE_NAME, INTERFACE_DESC
    );
}

/// Print available DLTs for the interface
fn print_dlts() {
    println!(
        "dlt {{number={}}}{{name=USER15}}{{display=Crazyflie CRTP}}",
        DLT_USER15
    );
}

/// Print configuration options
fn print_config() {
    // No configuration options for now
    // Could add socket path configuration in the future
}

/// Run packet capture
fn run_capture(fifo_path: &PathBuf) {
    // Remove existing socket if present
    let _ = std::fs::remove_file(SOCKET_PATH);

    // Create Unix socket listener
    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to create Unix socket: {}", e);
            std::process::exit(1);
        }
    };

    // Open FIFO for writing PCAP data
    let file = match File::create(fifo_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open FIFO: {}", e);
            std::process::exit(1);
        }
    };

    // Create PCAP writer with USER15 data link type
    let header = PcapHeader {
        datalink: pcap_file::DataLink::USER15,
        ..Default::default()
    };

    let mut pcap_writer = match PcapWriter::with_header(file, header) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Failed to create PCAP writer: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!("Crazyflie extcap: listening on {}", SOCKET_PATH);

    // Accept connections and forward packets
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                eprintln!("Crazyflie extcap: client connected");
                handle_client(&mut stream, &mut pcap_writer);
            }
            Err(e) => {
                eprintln!("Connection error: {}", e);
            }
        }
    }
}

/// Handle a connected client, reading packets and writing to PCAP
fn handle_client<W: Write>(stream: &mut std::os::unix::net::UnixStream, pcap_writer: &mut PcapWriter<W>) {
    let mut header_buf = [0u8; 26]; // link_type(1) + direction(1) + address(12) + channel(1) + devid(1) + timestamp(8) + len(2)

    loop {
        // Read packet header
        match stream.read_exact(&mut header_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                eprintln!("Crazyflie extcap: client disconnected");
                break;
            }
            Err(e) => {
                eprintln!("Error reading from client: {}", e);
                break;
            }
        }

        // Parse header
        let link_type = header_buf[0];
        let direction = header_buf[1];
        let address = &header_buf[2..14];
        let channel = header_buf[14];
        let devid = header_buf[15];
        let timestamp_us = u64::from_le_bytes(header_buf[16..24].try_into().unwrap());
        let data_len = u16::from_le_bytes(header_buf[24..26].try_into().unwrap()) as usize;

        // Read packet data
        let mut data = vec![0u8; data_len];
        if let Err(e) = stream.read_exact(&mut data) {
            eprintln!("Error reading packet data: {}", e);
            break;
        }

        // Build dissector-compatible packet format:
        // | link_type | direction | address (5 or 12) | channel | devid | crtp_data |
        let address_len = if link_type == 1 { 5 } else { 12 }; // Radio=1 uses 5 bytes, USB=2 uses 12
        let mut pcap_data = Vec::with_capacity(1 + 1 + address_len + 1 + 1 + data.len());
        pcap_data.push(link_type);
        pcap_data.push(direction);
        pcap_data.extend_from_slice(&address[..address_len]);
        pcap_data.push(channel);
        pcap_data.push(devid);
        pcap_data.extend_from_slice(&data);

        // Convert timestamp
        let ts_sec = (timestamp_us / 1_000_000) as u32;
        let ts_usec = (timestamp_us % 1_000_000) as u32;

        // Write PCAP packet
        let packet = PcapPacket::new(
            std::time::Duration::new(ts_sec as u64, ts_usec * 1000),
            pcap_data.len() as u32,
            &pcap_data,
        );

        if let Err(e) = pcap_writer.write_packet(&packet) {
            eprintln!("Error writing PCAP packet: {}", e);
            break;
        }
    }
}
