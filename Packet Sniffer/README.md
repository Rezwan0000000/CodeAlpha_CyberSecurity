# 🛰️ Mega Packet Analyzer — Python Edition

A Professional Command-Line PCAP Inspector for Network Forensics, Blue/Red Teaming, and Capture-The-Flag (CTF) Challenges.

> Built with 🐍 Python, powered by Scapy & Colorama. Inspired by Wireshark — optimized for speed, stealth, and terminal.

---

## 🚀 Features

- **Wireshark-Style Tabular Output**  
  - Columns: `#`, `Timestamp`, `Protocol` (color-coded), `Source`, `Destination`, `Info` (smart summary)

- **Real-Time and Offline Modes**
  - Capture & inspect live traffic (sniff into `new_packet.pcap`)
  - Analyze existing `.pcap` files with advanced filters

- **True PCAP Order + Timestamps**
  - Display packets in original order with full timestamps

- **Powerful Filtering Engine**
  - Filter by: protocol, IP, port, Info column (grep-style)

- **Session & Flow Summary**
  - List conversations by IP/port pairs with packet counts

- **Pagination for Readability**
  - View 10 packets at a time with `m` / `more`

- **🔔 Smart Anomaly Alerts**
  - Detect SYN floods, port scans, oversized DNS queries, more

- **Export & Payload Dump**
  - Save filtered results to `filtered_output.pcap`
  - Dump TCP/raw payloads to `payload_dump.txt`

- **Theme Selection**
  - Built-in dark/light/default UI themes for comfortable viewing

---

## 🛠️ Installation

pip install scapy colorama


> 🔒 For live capture mode, run with **root** or **administrator** privileges.

---

## ⚡ Usage

### Start the Tool

python Packet_analysis.py


### Step 1: Choose Theme

- Select from **default**, **dark**, or **light** themes on startup

### Step 2: Choose Mode

- `1` — Live Capture & Analysis  
- `2` — Analyze Existing PCAP File

---

## 📡 Option 1: Live Capture

- Captures packets in real-time
- Displays one row per packet
- Stops with `Ctrl+C`
- Automatically saves to `new_packet.pcap`

<img width="1052" height="882" alt="image" src="https://github.com/user-attachments/assets/ead438a4-0655-4657-84fb-8fb470b6e817" />

---

## 🧠 Option 2: Analyze Existing PCAP

> Perfect for CTFs, malware PCAPs, and forensics!

### Apply Filters

- **IP Filter:** Show traffic from/to a specific host
- **Port Filter:** Focus on specific ports
- **Info Filter:** Grep-style search in the Info field

### Scroll Through Packets

- Use `m` or `more` to view the next 10 packets

### View Flow Summaries

- Type `flows` to highlight session-level conversations

### Export Results

- Save selected packets: `filtered_output.pcap`
- Dump payloads: `payload_dump.txt`

<img width="942" height="945" alt="image" src="https://github.com/user-attachments/assets/a14e217d-93a0-4c31-9a76-e8fa8d32e7ec" />

<img width="1066" height="875" alt="image" src="https://github.com/user-attachments/assets/2251dc03-2c9a-4cc8-bb43-15a2d22e05ff" />

---

## 🧠 Pro Forensics & CTF Moves

- 🔍 **Flows Mode** — See who’s talking, over what ports
- 🕵️ **Payload Extraction** — Reveal passwords, flags, or indicators
- 🚨 **Smart Alerts** — Spot suspicious behavior instantly
- ⚡ **Fast Triage** — Filter by protocol/IP/port/strings in seconds
- 🔢 **True Indexing** — "No." column tracks original PCAP rows

---

## 🤝 Contribute

PRs and Ideas Welcome!

We're open to protocol decoders, performance boosts, UI refinements, and more.

Make this the go-to packet analyzer for Bluesharpers, Red Teammers & 0x1337s.

---

## 📄 License

**MIT License**

Free to use, modify, and distribute — commercial or personal.

---

## 🙏 Acknowledgments

- Built with 💖 using [Scapy](https://scapy.net/) and [Colorama](https://pypi.org/project/colorama/)
- Inspired by [Wireshark](https://www.wireshark.org/) — rebuilt for power-users and terminal warriors

---

