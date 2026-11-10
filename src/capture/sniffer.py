#!/usr/bin/env python3
import time
import csv
import sys
import os
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest

DATASET_PATH = "data/processed/dataset_v1.csv"

class Flow:
    def __init__(self, flow_id, ip_version, label=0, scenario_id="E0"):
        self.flow_id = flow_id
        self.ip_version = ip_version
        self.start_time = time.time()
        self.last_time = time.time()
        self.packets = 0
        self.bytes = 0
        self.src_ports = set()
        self.dst_ports = set()
        self.proto_code = 0
        self.label = label
        self.scenario_id = scenario_id

    def update(self, pkt_len, proto, sport=None, dport=None):
        self.last_time = time.time()
        self.packets += 1
        self.bytes += pkt_len
        self.proto_code = proto
        if sport: self.src_ports.add(sport)
        if dport: self.dst_ports.add(dport)

    def to_csv_row(self):
        duration = max(self.last_time - self.start_time, 0.001)
        pps = round(self.packets / duration, 2)
        bps = round((self.bytes * 8) / duration, 2)
        
        return [
            self.flow_id,
            self.scenario_id,
            self.ip_version,
            self.proto_code,
            round(duration, 4),
            self.packets,
            self.bytes,
            pps,
            bps,
            len(self.dst_ports),
            self.label
        ]

flows = {}
CURRENT_SCENARIO = "E0"
CURRENT_LABEL = 0

def process_packet(packet):
    ip_version = 0
    src_ip, dst_ip = None, None
    proto = 0
    sport, dport = None, None

    if packet.haslayer(IP):
        ip_version = 4
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
    elif packet.haslayer(IPv6):
        ip_version = 6
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        proto = packet[IPv6].nh

    if not src_ip or not dst_ip:
        return

    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    flow_key = f"{src_ip}->{dst_ip}"
    
    if flow_key not in flows:
        flows[flow_key] = Flow(flow_key, ip_version, CURRENT_LABEL, CURRENT_SCENARIO)

    flows[flow_key].update(len(packet), proto, sport, dport)
    print(f"\r[*] Capturando [{CURRENT_SCENARIO}] - Flujos: {len(flows)} | Último: {flow_key}", end="")

def save_csv():
    os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
    file_exists = os.path.exists(DATASET_PATH)
    
    with open(DATASET_PATH, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "flow_id", "scenario_id", "ip_version", "protocol",
                "duration", "packets", "bytes", "pps", "bps",
                "unique_dst_ports", "label"
            ])
        for flow in flows.values():
            writer.writerow(flow.to_csv_row())
    print(f"\n[+] {len(flows)} flujos guardados exitosamente en {DATASET_PATH}")

if __name__ == "__main__":
    if len(sys.argv) > 2:
        CURRENT_SCENARIO = sys.argv[1]
        CURRENT_LABEL = int(sys.argv[2])

    print(f"[*] Modo Recolección Dataset - Escenario: {CURRENT_SCENARIO} (Label={CURRENT_LABEL})")
    try:
        sniff(filter="", prn=process_packet, store=0, timeout=10)
    except KeyboardInterrupt:
        pass
    finally:
        save_csv()