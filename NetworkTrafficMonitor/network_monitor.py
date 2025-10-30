# network_monitor.py
"""
Network Traffic Monitor (light)
- Requires: scapy, colorama
- Run as Administrator on Windows
"""

import argparse
import json
from collections import Counter
from datetime import datetime
from colorama import init as colorama_init, Fore, Style
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list

colorama_init(autoreset=True)

def list_interfaces():
    ifs = get_if_list()
    print("Available interfaces:")
    for i, iface in enumerate(ifs):
        print(f"  [{i}] {iface}")
    return ifs

def packet_summary(pkt):
    """Return a simple summary dict for logging."""
    try:
        if IP not in pkt:
            return None
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = "OTHER"
        if TCP in pkt:
            proto = "TCP"
        elif UDP in pkt:
            proto = "UDP"
        elif ICMP in pkt:
            proto = "ICMP"
        return {"time": datetime.utcnow().isoformat(), "src": src, "dst": dst, "proto": proto}
    except Exception:
        return None

class Monitor:
    def __init__(self, iface=None, bpf=None, log_file=None, top_talkers_limit=10):
        self.iface = iface
        self.bpf = bpf  # BPF filter string for sniff
        self.log_file = log_file
        self.top_talkers = Counter()
        self.top_talkers_limit = top_talkers_limit

    def _print_packet(self, summary):
        proto = summary["proto"]
        src = summary["src"]
        dst = summary["dst"]
        color = Fore.WHITE
        if proto == "TCP":
            color = Fore.CYAN
        elif proto == "UDP":
            color = Fore.GREEN
        elif proto == "ICMP":
            color = Fore.YELLOW
        print(f"{color}[{proto}] {src} -> {dst}{Style.RESET_ALL}")

    def _log_packet(self, summary):
        if not self.log_file or summary is None:
            return
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(summary) + "\n")

    def _handle_pkt(self, pkt):
        summary = packet_summary(pkt)
        if not summary:
            return
        self._print_packet(summary)
        self._log_packet(summary)
        # update top talkers (source counts)
        self.top_talkers.update([summary["src"]])

    def start(self, count=0):
        print(Fore.MAGENTA + "=== Network Traffic Monitor ===" + Style.RESET_ALL)
        print(f"Interface: {self.iface or 'default'}, Filter: {self.bpf or 'none'}")
        print("Press Ctrl+C to stop\n")
        sniff(filter=self.bpf, iface=self.iface, prn=self._handle_pkt, store=False, count=count)

    def print_top_talkers(self, n=None):
        n = n or self.top_talkers_limit
        print("\n" + Fore.BLUE + "=== Top Talkers ===" + Style.RESET_ALL)
        for ip, cnt in self.top_talkers.most_common(n):
            print(f"{ip}: {cnt} packets")

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Monitor (Scapy)")
    parser.add_argument("--iface", help="Interface name (or index) to listen on", default=None)
    parser.add_argument("--protocol", help="Protocol filter: tcp | udp | icmp (BPF)", choices=["tcp", "udp", "icmp"], default=None)
    parser.add_argument("--log", help="Append JSON summaries to this file", default=None)
    parser.add_argument("--count", help="Number of packets to capture (0 = infinite)", type=int, default=0)
    parser.add_argument("--list-ifaces", help="List available interfaces and exit", action="store_true")
    parser.add_argument("--top", help="Show top N talkers after capture", type=int, default=10)
    args = parser.parse_args()

    if args.list_ifaces:
        list_interfaces()
        return

    bpf = args.protocol if args.protocol else None

    # If iface is numeric index, convert to name
    iface = args.iface
    if iface and iface.isdigit():
        idx = int(iface)
        ifaces = get_if_list()
        if 0 <= idx < len(ifaces):
            iface = ifaces[idx]
        else:
            print("Invalid interface index.")
            return

    monitor = Monitor(iface=iface, bpf=bpf, log_file=args.log, top_talkers_limit=args.top)
    try:
        monitor.start(count=args.count)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    finally:
        monitor.print_top_talkers()

if __name__ == "__main__":
    main()
