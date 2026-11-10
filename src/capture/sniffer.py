#!/usr/bin/env python3
"""
FireNet-AI - Sniffer y Recolector de Datos para Dataset
Captura tráfico en tiempo real, agrega flujos bidireccionales mediante FlowExtractor
y genera registros con el esquema requerido por la Fase 2 del ROADMAP:
[flow_id, run_id, scenario_id, ip_version, protocol, duration, packets, bytes,
 pps, bps, pkts_fwd, pkts_rev, ratio_pkts, mean_pkt_size, src_port, dst_port, syn_flag, label]
"""

import os
import sys
import csv
import time
import argparse
from pathlib import Path

# Permitir importaciones relativas desde la raíz del proyecto
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features.extractor import FlowExtractor

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
    from scapy.layers.inet6 import (
        ICMPv6EchoRequest,
        ICMPv6EchoReply,
        ICMPv6ND_NS,
        ICMPv6ND_NA,
        ICMPv6ND_RA,
        ICMPv6ND_RS,
    )
except ImportError as e:
    print(f"[ERROR] Error al importar scapy: {e}. Instálalo con 'pip install scapy' o vía tu gestor de paquetes.")
    sys.exit(1)

DEFAULT_DATASET_PATH = "data/processed/dataset_v1.csv"

CSV_HEADERS = [
    "flow_id", "run_id", "scenario_id",
    "ip_version", "protocol", "duration",
    "packets", "bytes", "pps", "bps",
    "pkts_fwd", "pkts_rev", "ratio_pkts",
    "mean_pkt_size", "src_port", "dst_port",
    "syn_flag", "label"
]


class DatasetCollector:
    def __init__(self, scenario_id="E0", label=0, run_id="RUN_001",
                 output_path=DEFAULT_DATASET_PATH, window_seconds=2.0,
                 attacker_ips=None, client_ips=None, save_pcap=None):
        self.scenario_id = scenario_id
        self.default_label = label
        self.run_id = run_id
        self.output_path = output_path
        self.extractor = FlowExtractor(window_seconds=window_seconds)
        self.total_packets_seen = 0
        self.attacker_ips = set(attacker_ips or ["10.0.3.10", "192.168.30.2", "fd00:3::10"])
        self.client_ips = set(client_ips or ["10.0.1.10", "192.168.10.2", "fd00:1::10"])
        self.collected_rows = []
        self.save_pcap = save_pcap
        self.pcap_writer = None
        if self.save_pcap:
            os.makedirs(os.path.dirname(os.path.abspath(self.save_pcap)), exist_ok=True)
            from scapy.utils import PcapWriter
            self.pcap_writer = PcapWriter(self.save_pcap, append=True, sync=True)

    def _extract_tcp_flags(self, packet):
        flags = set()
        if packet.haslayer(TCP):
            raw_flags = packet[TCP].flags
            if raw_flags & 0x02: flags.add("SYN")
            if raw_flags & 0x10: flags.add("ACK")
            if raw_flags & 0x01: flags.add("FIN")
            if raw_flags & 0x04: flags.add("RST")
            if raw_flags & 0x08: flags.add("PSH")
            if raw_flags & 0x20: flags.add("URG")
        return flags

    def process_packet(self, packet):
        ip_version = 0
        src_ip, dst_ip = None, None
        protocol = 0
        src_port, dst_port = 0, 0

        # Ignorar paquetes de control IPv6 de descubrimiento local (NDP/Router Advertisement)
        if (packet.haslayer(ICMPv6ND_NS) or packet.haslayer(ICMPv6ND_NA) or 
            packet.haslayer(ICMPv6ND_RA) or packet.haslayer(ICMPv6ND_RS)):
            return

        if packet.haslayer(IP):
            ip_version = 4
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            # Filtrar loopback y multicast local
            if src_ip.startswith("127.") or dst_ip.startswith("127.") or dst_ip.startswith("224."):
                return
        elif packet.haslayer(IPv6):
            ip_version = 6
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            protocol = packet[IPv6].nh
            # Filtrar loopback IPv6 y multicast de enlace
            if src_ip == "::1" or dst_ip.startswith("ff02::") or src_ip.startswith("fe80::"):
                return
        else:
            return

        if not src_ip or not dst_ip:
            return

        # Capa de transporte
        tcp_flags = set()
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = self._extract_tcp_flags(packet)
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = 1
        elif packet.haslayer(ICMPv6EchoRequest) or packet.haslayer(ICMPv6EchoReply):
            protocol = 58

        pkt_metadata = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'ip_version': ip_version,
            'length': len(packet),
            'timestamp': getattr(packet, 'time', time.time()),
            'tcp_flags': tcp_flags
        }

        self.extractor.process_packet(pkt_metadata)
        self.total_packets_seen += 1
        if self.pcap_writer:
            try:
                self.pcap_writer.write(packet)
            except Exception:
                pass

        print(f"\r[*] Capturando [{self.scenario_id}|{self.run_id}] - Pkts: {self.total_packets_seen} | Flujos activos: {len(self.extractor.flows)}", end="", flush=True)

    def determine_label(self, flow_features):
        """
        Determina la etiqueta de un flujo:
        - Si el escenario es E0 (Benigno) -> 0
        - Si es un escenario de ataque (E1-E5):
          Si el iniciador es el cliente legítimo conocido -> 0
          Si el iniciador es el atacante -> 1
          Por defecto, si no se distingue, utiliza el default_label.
        """
        if self.scenario_id == "E0":
            return 0

        initiator = flow_features.get('initiator_ip')
        if initiator in self.client_ips:
            return 0
        if initiator in self.attacker_ips:
            return 1

        return self.default_label

    def flush_flows(self, force_all=True):
        if self.pcap_writer:
            try:
                self.pcap_writer.close()
            except Exception:
                pass
            self.pcap_writer = None

        extracted = self.extractor.extract_features(force_all=force_all)
        rows_to_save = []

        for flow_id, feat in extracted:
            lbl = self.determine_label(feat)
            row = [
                flow_id,
                self.run_id,
                self.scenario_id,
                feat['ip_version'],
                feat['protocol'],
                feat['duration'],
                feat['packets'],
                feat['bytes'],
                feat['pps'],
                feat['bps'],
                feat['pkts_fwd'],
                feat['pkts_rev'],
                feat['ratio_pkts'],
                feat['mean_pkt_size'],
                feat['src_port'],
                feat['dst_port'],
                feat['syn_flag'],
                lbl
            ]
            rows_to_save.append(row)

        if rows_to_save:
            self._save_to_csv(rows_to_save)
            self.collected_rows.extend(rows_to_save)
            print(f"\n[+] Guardados {len(rows_to_save)} flujos procesados en {self.output_path}")

    def _save_to_csv(self, rows):
        os.makedirs(os.path.dirname(os.path.abspath(self.output_path)), exist_ok=True)
        file_exists = os.path.exists(self.output_path) and os.path.getsize(self.output_path) > 0

        with open(self.output_path, mode='a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(CSV_HEADERS)
            writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description="FireNet-AI Network Sniffer & Flow Feature Collector")
    parser.add_argument("--scenario", "-s", default="E0",
                        help="ID del escenario (ej. E0=Benigno, E1=Scan, E2=Bruteforce, E3=DDoS, E4=Exfiltration, E5=Stealth)")
    parser.add_argument("--label", "-l", type=int, default=None,
                        help="Etiqueta objetivo (0=Benigno, 1=Malicioso). Por defecto: 0 para E0, 1 para E1-E5.")
    parser.add_argument("--run-id", "-r", default=None,
                        help="ID de la corrida (ej. RUN_001). Si no se indica, se autogenera.")
    parser.add_argument("--interface", "-i", default=None,
                        help="Interfaz de red para capturar (ej. veth-gw-c, veth-gw-t, o any)")
    parser.add_argument("--timeout", "-t", type=int, default=15,
                        help="Duración de la captura en segundos (0 para indefinido hasta Ctrl+C)")
    parser.add_argument("--window", "-w", type=float, default=2.0,
                        help="Ventana de agregación de flujos en segundos (default: 2.0)")
    parser.add_argument("--output", "-o", default=DEFAULT_DATASET_PATH,
                        help=f"Ruta del archivo CSV de destino (default: {DEFAULT_DATASET_PATH})")
    parser.add_argument("--bpf", default="",
                        help="Filtro BPF opcional para Scapy (ej. 'ip or ip6')")
    parser.add_argument("--offline", "--pcap", dest="pcap", default=None,
                        help="Ruta a un archivo .pcap para procesamiento offline")
    parser.add_argument("--save-pcap", default=None,
                        help="Ruta de archivo .pcap donde guardar los paquetes crudos capturados")

    args = parser.parse_args()

    # Asignar label por defecto según escenario
    if args.label is None:
        label = 0 if args.scenario == "E0" else 1
    else:
        label = args.label

    # Autogenerar run_id si no se provee
    if args.run_id is None:
        run_id = f"RUN_{args.scenario}_{int(time.time())}"
    else:
        run_id = args.run_id

    collector = DatasetCollector(
        scenario_id=args.scenario,
        label=label,
        run_id=run_id,
        output_path=args.output,
        window_seconds=args.window,
        save_pcap=args.save_pcap
    )

    print("=" * 60)
    print(" FireNet-AI Flow Sniffer & Feature Extractor (Fase 2)")
    print("=" * 60)
    print(f" Escenario     : {args.scenario} (Label={label})")
    print(f" Run ID        : {run_id}")
    print(f" Origen        : {args.pcap or args.interface or 'Default / Any (Live)'}")
    print(f" Timeout       : {args.timeout}s" if (args.timeout > 0 and not args.pcap) else " Timeout       : N/A")
    print(f" Destino CSV   : {args.output}")
    if args.save_pcap:
        print(f" Guardar PCAP  : {args.save_pcap}")
    print("=" * 60)

    sniff_kwargs = {
        'prn': collector.process_packet,
        'store': 0
    }
    if args.pcap:
        sniff_kwargs['offline'] = args.pcap
    else:
        if args.interface:
            sniff_kwargs['iface'] = args.interface
        if args.bpf:
            sniff_kwargs['filter'] = args.bpf
        if args.timeout > 0:
            sniff_kwargs['timeout'] = args.timeout

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print("\n[*] Captura interrumpida por el usuario.")
    except Exception as e:
        print(f"\n[ERROR durante la captura]: {e}")
    finally:
        collector.flush_flows(force_all=True)
        print(f"\n[+] Proceso finalizado. Total paquetes procesados: {collector.total_packets_seen}")


if __name__ == "__main__":
    main()
