import sys
import time
from collections import defaultdict, Counter
from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR
try:
    from scapy.layers.http import HTTPRequest
except ImportError:
    class HTTPRequest:
        pass
from colorama import init, Fore, Style

init(autoreset=True)

# THEMES
THEMES = {
    'default': {
        'TCP': Fore.CYAN, 'UDP': Fore.YELLOW, 'ICMP': Fore.MAGENTA,
        'HTTP': Fore.GREEN, 'DNS': Fore.BLUE, 'OTHER': Fore.LIGHTBLACK_EX,
        'HEADER': Fore.WHITE, 'SRC': Fore.GREEN, 'DST': Fore.RED,
        'INFO': Fore.YELLOW, 'WARN': Fore.LIGHTRED_EX, 'GREY': Fore.LIGHTBLACK_EX,
        'TIME': Fore.BLUE,
    },
    'dark': {
        'TCP': Fore.LIGHTCYAN_EX, 'UDP': Fore.LIGHTYELLOW_EX, 'ICMP': Fore.LIGHTMAGENTA_EX,
        'HTTP': Fore.LIGHTGREEN_EX, 'DNS': Fore.CYAN, 'OTHER': Fore.LIGHTBLACK_EX,
        'HEADER': Fore.LIGHTWHITE_EX, 'SRC': Fore.LIGHTGREEN_EX, 'DST': Fore.LIGHTRED_EX,
        'INFO': Fore.LIGHTYELLOW_EX, 'WARN': Fore.LIGHTRED_EX, 'GREY': Fore.LIGHTBLACK_EX,
        'TIME': Fore.LIGHTBLUE_EX,
    },
    'light': {
        'TCP': Fore.BLUE, 'UDP': Fore.YELLOW, 'ICMP': Fore.MAGENTA,
        'HTTP': Fore.GREEN, 'DNS': Fore.CYAN, 'OTHER': Fore.LIGHTBLACK_EX,
        'HEADER': Fore.WHITE, 'SRC': Fore.GREEN, 'DST': Fore.RED,
        'INFO': Fore.YELLOW, 'WARN': Fore.RED, 'GREY': Fore.LIGHTBLACK_EX,
        'TIME': Fore.BLUE,
    }
}

theme_choice = 'default'
THEME = THEMES[theme_choice]

def choose_theme():
    global THEME
    print("Select color theme: [default/dark/light]")
    th = input().strip().lower()
    if th in THEMES:
        THEME = THEMES[th]
    print(Style.RESET_ALL)

def time_str(pkt):
    try:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(pkt.time)))
    except Exception:
        return '??'

def get_protocol(pkt):
    if pkt.haslayer(HTTPRequest):
        return 'HTTP'
    elif pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        return 'DNS'
    elif pkt.haslayer(TCP):
        return 'TCP'
    elif pkt.haslayer(UDP):
        return 'UDP'
    elif pkt.haslayer(ICMP):
        return 'ICMP'
    else:
        # Heuristic guess by port
        if TCP in pkt:
            if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                return 'TLS?'
            if pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
                return 'SSH?'
        return 'OTHER'

def color_proto(proto):
    return THEME.get(proto, Fore.WHITE)

def get_info(pkt, alertflags=None):
    alert = ""
    info = ""
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode(errors='replace')
        qtype = pkt[DNSQR].qtype
        info = f"DNS Query: {qname} (type {qtype})"
        if alertflags is not None and pkt[UDP].len > 512:
            alert = THEME['WARN'] + " [Suspicious large DNS!]"
    elif pkt.haslayer(HTTPRequest):
        req = pkt[HTTPRequest]
        try:
            method = req.Method.decode()
            path = req.Path.decode()
            host = req.Host.decode() if hasattr(req, 'Host') else ''
            info = f"HTTP: {method} {path} Host: {host}"
        except:
            info = "HTTP Request"
    elif pkt.haslayer(ICMP):
        t = pkt[ICMP].type
        code = pkt[ICMP].code
        types = {0:"Echo Reply",3:"Dest Unreachable",5:"Redirect",8:"Echo Request",11:"Time Exceeded"}
        info = f"ICMP {types.get(t, 'Type '+str(t))} (Code {code})"
    elif pkt.haslayer(TCP):
        flags = pkt[TCP].sprintf("%flags%")
        details = []
        if "S" in flags: details.append("SYN")
        if "A" in flags: details.append("ACK")
        if "F" in flags: details.append("FIN")
        if "R" in flags: details.append("RST")
        if "P" in flags: details.append("PUSH")
        if pkt.haslayer(Raw):
            try:
                dat = pkt[Raw].load
                snippet = dat[:30].decode('utf-8', 'replace').replace("\n", ' ').replace("\r", '')
                details.append(f"Data: {snippet}")
            except:
                pass
        info = "TCP " + "/".join(details)
        # Attack heuristics
        if alertflags is not None:
            if flags == "S":
                alertflags['syn'][pkt[IP].src] += 1
                if alertflags['syn'][pkt[IP].src] > 30:
                    alert += THEME['WARN'] + "[SYN flood?]"
            if flags == "S" and pkt[TCP].dport in [21,22,23,80,443,3389]:
                alert += THEME['WARN'] + "[Scan?]"
    elif pkt.haslayer(UDP):
        info = "UDP Data"
    elif pkt.haslayer(Raw):
        raw = pkt[Raw].load[:30]
        snippet = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
        info = f"Raw: {snippet}"
    # Optionally add alerts
    return f"{THEME['INFO']}{info}{Style.RESET_ALL}{alert if alert else ''}"

def ws_row(idx, pkt, ts, info_str, theme=THEME):
    proto = get_protocol(pkt)
    color = color_proto(proto)
    src = pkt[IP].src if pkt.haslayer(IP) else "—"
    dst = pkt[IP].dst if pkt.haslayer(IP) else "—"
    return f"{Style.BRIGHT}{theme['HEADER']}{str(idx):>5}{Style.RESET_ALL} " \
           f"{theme['TIME']}{ts}{Style.RESET_ALL} " \
           f"{color}{proto:<7}{Style.RESET_ALL} " \
           f"{theme['SRC']}{src:<15} {theme['DST']}{dst:<15} " \
           f"{info_str}{Style.RESET_ALL}"

def print_header():
    print(f"{Style.BRIGHT}{THEME['HEADER']}{'No.':>5} {'Date/Time':<19} {'Proto':<7} {'Source':<15} {'Destination':<15} Info{Style.RESET_ALL}")

def protocol_summary(pkts):
    stats = Counter()
    for pkt in pkts:
        stats[get_protocol(pkt)] += 1
    return stats

def search_filter(pkt, searchstr):
    if not searchstr:
        return True
    info = get_info(pkt)
    return (searchstr.lower() in info.lower())

def paginated_view(filtered, all_packets, alertflags, grep):
    print_header()
    idx, per_page = 0, 20
    total = len(filtered)
    while idx < total:
        for pkt in filtered[idx:idx+per_page]:
            true_idx = all_packets.index(pkt) + 1
            ts = time_str(pkt)
            info_str = get_info(pkt, alertflags=alertflags)
            if grep and grep.lower() not in info_str.lower():
                continue
            print(ws_row(true_idx, pkt, ts, info_str))
        idx += per_page
        if idx >= total:
            print(THEME['WARN'] + f"\n[✔] End of packet list.\n{Style.RESET_ALL}")
            break
        user_input = input(THEME['INFO'] + Style.BRIGHT +
                      "\nType 'm' or 'more' to show 10 more, or just [ENTER] to select another protocol: ").strip().lower()
        if user_input in ['m', 'more']:
            per_page = 10
        else:
            break

def summarize_flows(pkts, proto_filter=None):
    flows = Counter()
    for pkt in pkts:
        if IP in pkt and (proto_filter is None or get_protocol(pkt) == proto_filter):
            if TCP in pkt:
                key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                flows[key] += 1
            elif UDP in pkt:
                key = (pkt[IP].src, pkt[UDP].sport, pkt[IP].dst, pkt[UDP].dport)
                flows[key] += 1
    print(f"\nConversation/Session Summary ({proto_filter if proto_filter else 'ALL'}):")
    print(f"{'SrcIP':<15} {'SPort':<6} {'DstIP':<15} {'DPort':<6} {'Count':<8}")
    for k, cnt in flows.most_common(15):
        print(f"{k[0]:<15} {k[1]:<6} {k[2]:<15} {k[3]:<6} {cnt:<8}")

def analyze_existing():
    filename = input("Enter pcap filename: ").strip()
    if filename.endswith(".pcapng"):
        print(THEME['WARN'] + "[!] Warning: pcapng support is partial in Scapy. Prefer .pcap files.")
    try:
        pkts = rdpcap(filename)
    except Exception as e:
        print(THEME['WARN'] + f"[!] Error reading PCAP: {e}")
        return

    stats = protocol_summary(pkts)
    print("\nPacket Protocol Summary:\n-------------------------")
    print("| Protocol | Packet Count |")
    print("|----------|--------------|")
    for proto, count in stats.items():
        print(f"| {proto:<8} | {count:<12}|")
    print("-------------------------\n")

    proto_keys = list(stats.keys())
    alertflags = defaultdict(lambda: defaultdict(int))
    while True:
        try:
            sel = input("Protocol ({}), or Ctrl+C to exit, [flows] for session summary: ".format('/'.join(proto_keys))).strip().upper()
        except KeyboardInterrupt:
            print("\nExiting protocol view.")
            break
        if not sel:
            continue
        if sel == "FLOWS":
            fkey = input("Show flows for protocol? (e.g. TCP/UDP/ENTER for all): ").strip().upper()
            summarize_flows(pkts, proto_filter=fkey if fkey else None)
            continue
        if sel not in stats:
            print("Please choose a valid protocol.")
            continue

        ip_filter = input("Filter by IP (src/dst) [ENTER to skip]: ").strip()
        port_filter = input("Filter by Port (src/dst) [ENTER to skip]: ").strip()
        grep = input("Search keyword in Info field [ENTER to skip]: ").strip()

        filtered_packets = [
            pkt for pkt in pkts
            if get_protocol(pkt) == sel
            and (not ip_filter or (
                    (pkt.haslayer(IP) and (pkt[IP].src == ip_filter or pkt[IP].dst == ip_filter))))
            and (not port_filter or (
                    (TCP in pkt and (str(pkt[TCP].sport) == port_filter or str(pkt[TCP].dport) == port_filter))
                    or (UDP in pkt and (str(pkt[UDP].sport) == port_filter or str(pkt[UDP].dport) == port_filter))
            ))
            and search_filter(pkt, grep)
        ]
        if not filtered_packets:
            print(THEME['WARN'] + f"No packets found for selected filter.")
            continue

        paginated_view(filtered_packets, pkts, alertflags, grep)

        export = input("Export these packets to a pcap file? (y/n): ").strip().lower()
        if export == 'y':
            wrpcap("filtered_output.pcap", filtered_packets)
            print(Fore.GREEN + "[✔] Exported to filtered_output.pcap")
        dump = input("Dump TCP/Raw payloads to payload_dump.txt? (y/n): ").strip().lower()
        if dump == 'y':
            with open("payload_dump.txt", "w") as f:
                for pkt in filtered_packets:
                    if pkt.haslayer(Raw):
                        try:
                            f.write(pkt[Raw].load.decode('utf-8', errors='ignore') + '\n')
                        except:
                            pass
            print(Fore.GREEN + "[✔] Payload dump saved to payload_dump.txt")

def live_capture():
    captured = []
    print_header()
    def pkt_callback(pkt):
        captured.append(pkt)
        info_str = get_info(pkt)
        print(ws_row(len(captured), pkt, time_str(pkt), info_str))

    print(THEME['INFO'] + "[+] Capturing packets... Press Ctrl+C to stop.\n")
    try:
        sniff(prn=pkt_callback, store=True)
    except KeyboardInterrupt:
        print(THEME['WARN'] + f"\n[+] Capture stopped at {len(captured)} packets.")

    if captured:
        wrpcap("new_packet.pcap", captured)
        print(THEME['INFO'] + "\n[✔] Packets saved to 'new_packet.pcap'.")
    else:
        print(THEME['WARN'] + "[!] No packets were captured.")

def main():
    print(f"{Style.BRIGHT}{THEME['HEADER']}Wireshark-Style Packet Analyzer (Professional Edition){Style.RESET_ALL}")
    choose_theme()
    print("1) Capture and analyze real-time network traffic")
    print("2) Analyze an existing pcap file\n")
    opt = input("Select option (1 or 2): ").strip()
    if opt == '1':
        live_capture()
    elif opt == '2':
        analyze_existing()
    else:
        print(THEME['WARN'] + "[!] Invalid option. Please select 1 or 2.")

if __name__ == "__main__":
    main()
