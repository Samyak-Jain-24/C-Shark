KEHDE

# C-Shark: The Terminal Packet Sniffer

A comprehensive command-line network packet analyzer built in C using libpcap. C-Shark provides deep packet inspection capabilities with layer-by-layer analysis from Ethernet to Application layer.

## Features

### Phase 1: Interface Discovery & Basic Capture
- **Device Discovery**: Automatically scans and lists all available network interfaces
- **Interface Selection**: Interactive menu for choosing which interface to monitor
- **Live Packet Capture**: Real-time packet capture with basic information display
- **Graceful Controls**: Proper handling of Ctrl+C (stop capture) and Ctrl+D (exit)

### Phase 2: Layer-by-Layer Packet Dissection
- **Layer 2 (Ethernet)**: MAC addresses, EtherType identification (IPv4, IPv6, ARP)
- **Layer 3 (Network)**:
  - **IPv4**: Source/Destination IPs, Protocol, TTL, Packet ID, Total Length, Header Length, Flags
  - **IPv6**: Source/Destination IPs, Next Header, Hop Limit, Traffic Class, Flow Label, Payload Length
  - **ARP**: Operation type, Sender/Target IP and MAC addresses, Hardware/Protocol types
- **Layer 4 (Transport)**:
  - **TCP**: Source/Destination ports (with service identification), Sequence/ACK numbers, Flags, Window size, Checksum, Header length
  - **UDP**: Source/Destination ports (with service identification), Length, Checksum
- **Layer 7 (Application)**: Protocol identification and hex dump of first 64 bytes

### Phase 3: Advanced Filtering
- **Protocol Filters**: HTTP, HTTPS, DNS, ARP, TCP, UDP
- **Real-time Filtering**: Apply filters during live capture
- **Berkeley Packet Filter**: Efficient kernel-level filtering using libpcap

### Phase 4: Session Management
- **Packet Storage**: Stores up to 10,000 packets from the last session
- **Memory Management**: Automatic cleanup between sessions to prevent memory leaks
- **Session Persistence**: Maintains packet data for post-capture analysis

### Phase 5: Detailed Packet Inspection
- **Session Summary**: Overview of all captured packets with basic information
- **In-depth Analysis**: Comprehensive breakdown of individual packets
- **Full Hex Dumps**: Complete packet frame display in hex format
- **Interactive Selection**: Choose specific packets for detailed inspection

## Installation

### Prerequisites
- Linux operating system (tested on Ubuntu/Debian)
- GCC compiler
- libpcap development library
- Root privileges for packet capture

### Install Dependencies
```bash
# On Ubuntu/Debian:
sudo apt-get update
sudo apt-get install libpcap-dev gcc make

# Or use the Makefile target:
make install-deps
```

### Build
```bash
# Clone/navigate to the project directory
cd /path/to/cshark

# Compile the project
make

# The executable 'cshark' will be created
```

## Usage

### Basic Usage
```bash
# Run C-Shark (requires root privileges)
sudo ./cshark
```

### Available Make Targets
```bash
make                # Build the project
make clean          # Clean build artifacts
make run            # Build and run with sudo
make debug          # Build with debugging symbols
make memcheck       # Run with valgrind memory checking
make install-deps   # Install required dependencies
```

### Interface Selection
1. When started, C-Shark will scan for available network interfaces
2. Select an interface by entering its number
3. Common interfaces:
   - `wlan0`: Wireless interface
   - `eth0`: Ethernet interface
   - `lo`: Loopback interface
   - `any`: Capture on all interfaces

### Menu Options
1. **Start Sniffing (All Packets)**: Capture and display all packets in real-time
2. **Start Sniffing (With Filters)**: Apply protocol filters before capture
3. **Inspect Last Session**: Review previously captured packets
4. **Exit C-Shark**: Clean exit from the application

### Example Output
```
-----------------------------------------
Packet #1113 | Timestamp: 12:34:56.553060 | Length: 66 bytes
L2 (Ethernet): Dst MAC: E6:51:4A:2D:B0:F9 | Src MAC: B4:8C:9D:5D:86:A1 | EtherType: IPv4 (0x0800)
L3 (IPv4): Src IP: 34.107.221.82 | Dst IP: 10.2.130.118 | Protocol: TCP (6) | TTL: 118
ID: 0xA664 | Total Length: 52 | Header Length: 20 bytes
L4 (TCP): Src Port: 443 (HTTPS) | Dst Port: 35554 | Seq: 4016914192 | Ack: 0 | Flags: [SYN]
Window: 64800 | Checksum: 0x804D | Header Length: 32 bytes
L7 (Payload): Identified as HTTPS/TLS on port 443 - 93 bytes
Data (first 64 bytes):
16 03 03 00 25 10 00 00 21 20 A3 F9 BF D4 D4 6C ....%...! .....l
CC 8F CC E8 61 9C 93 F0 09 1A DB A7 F0 41 BF 78 ....a........A.x
01 23 86 B2 08 F0 CB 11 12 36 14 03 03 00 01 01 .#.......6......
16 03 03 00 28 00 00 00 00 00 00 00 00 5E B6 F2 ....(........^..
```

## Architecture

### Project Structure
```
cshark_project/
├── Makefile
├── README.md
├── include/
│   ├── dissector.h    # Packet dissection functions
│   ├── sniffer.h      # Main sniffer declarations
│   ├── storage.h      # Packet storage management
│   └── utils.h        # Utility functions
└── src/
    ├── dissector.c    # Layer-by-layer packet analysis
    ├── main.c         # Main program and UI
    ├── sniffer.c      # Interface discovery and capture
    ├── storage.c      # Packet storage and session management
    └── utils.c        # Helper and utility functions
```

### Key Components
- **Interface Discovery**: Uses `pcap_findalldevs()` to enumerate network interfaces
- **Packet Capture**: Employs `pcap_open_live()` and `pcap_loop()` for live capture
- **Protocol Dissection**: Modular approach with separate functions for each layer
- **Memory Management**: Careful allocation/deallocation to prevent memory leaks
- **Signal Handling**: Proper cleanup on interruption signals

## Supported Protocols

### Layer 2 (Data Link)
- Ethernet II frames

### Layer 3 (Network)
- IPv4 (Internet Protocol version 4)
- IPv6 (Internet Protocol version 6)
- ARP (Address Resolution Protocol)

### Layer 4 (Transport)
- TCP (Transmission Control Protocol)
- UDP (User Datagram Protocol)
- ICMP (Internet Control Message Protocol)
- ICMPv6 (Internet Control Message Protocol version 6)

### Layer 7 (Application)
- HTTP (port 80)
- HTTPS/TLS (port 443)
- DNS (port 53)
- SSH (port 22)
- FTP (ports 20, 21)
- SMTP (port 25)
- And many more common services

## Filtering Options
- **HTTP**: Captures packets on port 80
- **HTTPS**: Captures packets on port 443
- **DNS**: Captures packets on port 53 (UDP and TCP)
- **ARP**: Captures only ARP packets
- **TCP**: Captures all TCP packets
- **UDP**: Captures all UDP packets

## Performance Considerations
- Maximum packet storage: 10,000 packets per session
- Efficient BPF filtering at kernel level
- Minimal processing overhead during capture
- Memory is automatically freed between sessions

## Security and Legal Notes
- **Root Privileges Required**: Packet capture requires elevated privileges
- **Passive Monitoring Only**: C-Shark only captures and analyzes packets, never sends or injects
- **Local Use Only**: Designed for legitimate network analysis and debugging
- **Legal Compliance**: Users are responsible for complying with local laws and network policies

## Troubleshooting

### Common Issues
1. **Permission Denied**: Run with `sudo`
2. **No Interfaces Found**: Check if libpcap is properly installed
3. **Compilation Errors**: Ensure all dependencies are installed
4. **No Packets Captured**: 
   - Check interface is active
   - Try different interface (e.g., 'lo' for localhost)
   - Verify network traffic exists

### Debug Mode
```bash
make debug
sudo ./cshark
```

### Memory Leak Detection
```bash
make memcheck
# Note: Requires valgrind installation
```

## Comparison with Wireshark
C-Shark provides similar packet analysis capabilities to Wireshark but with:
- **Terminal-only interface**: No GUI dependencies
- **Lightweight**: Minimal resource usage
- **Educational focus**: Clear, readable output format
- **Programmable**: Easy to modify and extend

## Future Enhancements
- Support for more Layer 7 protocols
- Packet filtering by content (regex matching)
- Export capabilities (PCAP format)
- Network statistics and analysis
- IPv6 extension header parsing
- VLAN tag support

## Contributing
This project is designed as an educational tool for understanding network protocols and packet analysis. Feel free to extend and modify according to your needs.

## License
Educational/Academic use. Please refer to your institution's policies regarding network monitoring tools.