//! Wireshark extcap for Crazyflie CRTP protocol
//!
//! This application implements the Wireshark extcap interface to capture
//! CRTP packets from Crazyflie applications using the crazyflie-link crate
//! with the "wireshark" feature enabled.

use clap::Parser;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use std::fs::File;
use std::io::Read;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};
use std::thread;

/// Wireshark extcap interface name
const INTERFACE_NAME: &str = "crazyflie";
/// Wireshark extcap interface description
const INTERFACE_DESC: &str = "Crazyflie CRTP";
/// Unix socket path for receiving packets from clients
const SOCKET_PATH: &str = "/tmp/crazyflie-capture.sock";
/// Wireshark USER15 data link type (147)
const DLT_USER15: u32 = 162;

/// Packet data sent from client handlers to the PCAP writer
struct CapturedPacket {
    timestamp_us: u64,
    data: Vec<u8>,
}

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

    // Create channel for packets from client handlers
    let (tx, rx) = mpsc::channel::<CapturedPacket>();

    // Spawn thread to accept connections
    thread::spawn(move || {
        let mut client_id = 0u32;
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    client_id += 1;
                    eprintln!("Crazyflie extcap: client {} connected", client_id);
                    let tx = tx.clone();
                    let id = client_id;
                    thread::spawn(move || {
                        handle_client(stream, tx, id);
                    });
                }
                Err(e) => {
                    eprintln!("Connection error: {}", e);
                }
            }
        }
    });

    // Main thread: receive packets and write to PCAP
    for packet in rx {
        let ts_sec = (packet.timestamp_us / 1_000_000) as u32;
        let ts_usec = (packet.timestamp_us % 1_000_000) as u32;

        let pcap_packet = PcapPacket::new(
            std::time::Duration::new(ts_sec as u64, ts_usec * 1000),
            packet.data.len() as u32,
            &packet.data,
        );

        if let Err(e) = pcap_writer.write_packet(&pcap_packet) {
            eprintln!("Error writing PCAP packet: {}", e);
            break;
        }
    }
}

/// Handle a connected client, reading packets and sending to channel
fn handle_client(mut stream: UnixStream, tx: Sender<CapturedPacket>, client_id: u32) {
    let mut header_buf = [0u8; 41]; // link_type(1) + direction(1) + address(12) + channel(1) + serial(16) + timestamp(8) + len(2)

    loop {
        // Read packet header
        match stream.read_exact(&mut header_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                eprintln!("Crazyflie extcap: client {} disconnected", client_id);
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
        let serial = &header_buf[15..31];
        let timestamp_us = u64::from_le_bytes(header_buf[31..39].try_into().unwrap());
        let data_len = u16::from_le_bytes(header_buf[39..41].try_into().unwrap()) as usize;

        // Read packet data
        let mut data = vec![0u8; data_len];
        if let Err(e) = stream.read_exact(&mut data) {
            eprintln!("Error reading packet data: {}", e);
            break;
        }

        // Build dissector-compatible packet format:
        // | link_type | direction | address (5 or 12) | channel | serial (16) | crtp_data |
        let address_len = if link_type == 1 { 5 } else { 12 }; // Radio=1 uses 5 bytes, USB=2 uses 12
        let mut pcap_data = Vec::with_capacity(1 + 1 + address_len + 1 + 16 + data.len());
        pcap_data.push(link_type);
        pcap_data.push(direction);
        pcap_data.extend_from_slice(&address[..address_len]);
        pcap_data.push(channel);
        pcap_data.extend_from_slice(serial);
        pcap_data.extend_from_slice(&data);

        // Send packet to main thread for PCAP writing
        if tx.send(CapturedPacket {
            timestamp_us,
            data: pcap_data,
        }).is_err() {
            // Receiver dropped, stop processing
            break;
        }
    }
}
