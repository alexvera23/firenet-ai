#!/usr/bin/env python3
"""
FireNet-AI - Orquestador Automatizado de Recolección de Datasets (Fase 2: Día 3)
Ejecuta la matriz completa de escenarios de tráfico (E0 a E5) en un entorno de red aislado,
captura los paquetes crudos (.pcap en data/raw/), agrega las características de flujos
mediante FlowExtractor y genera el dataset consolidado en data/processed/dataset_v1.csv.

Escenarios:
  - E0: Tráfico Benigno (HTTP GET, SSH legítimo, ICMP echo IPv4 e IPv6)
  - E1: Escaneo de Puertos (TCP Connect / SYN Scan en rangos amplios y bien conocidos)
  - E2: Fuerza Bruta (Ráfagas de autenticación SSH / HTTP POST)
  - E3: DDoS / Inundación (UDP flood y TCP SYN flood a alta tasa)
  - E4: Exfiltración de Datos (Transferencia masiva continua en ráfagas hacia sink)
  - E5: Escaneo Sigiloso / Low-and-Slow (Sondeo espaciado de baja frecuencia)
"""

import os
import sys
import time
import socket
import random
import threading
import subprocess
from pathlib import Path

# Configurar path del proyecto
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.capture.sniffer import DatasetCollector, DEFAULT_DATASET_PATH
from src.features.extractor import FlowExtractor

try:
    from scapy.all import (
        IP, IPv6, TCP, UDP, ICMP,
        Raw, Ether, wrpcap, sniff
    )
    from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply
except ImportError:
    print("[ERROR] scapy no está instalado en el entorno.")
    sys.exit(1)

RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_CSV = PROJECT_ROOT / DEFAULT_DATASET_PATH

CLIENT_IP4 = "10.0.1.10"
CLIENT_IP6 = "fd00:1::10"
ATTACKER_IP4 = "10.0.3.10"
ATTACKER_IP6 = "fd00:3::10"
TARGET_IP4 = "10.0.2.10"
TARGET_IP6 = "fd00:2::10"


# ==============================================================================
# CONFIGURACIÓN DEL ENTORNO DE RED AISLADO
# ==============================================================================

def configure_network_interfaces():
    """Configura las direcciones IP virtuales de la topología en la interfaz loopback."""
    cmds = [
        "ip link set lo up",
        f"ip addr add {CLIENT_IP4}/24 dev lo 2>/dev/null || true",
        f"ip addr add {ATTACKER_IP4}/24 dev lo 2>/dev/null || true",
        f"ip addr add {TARGET_IP4}/24 dev lo 2>/dev/null || true",
        f"ip -6 addr add {CLIENT_IP6}/64 dev lo 2>/dev/null || true",
        f"ip -6 addr add {ATTACKER_IP6}/64 dev lo 2>/dev/null || true",
        f"ip -6 addr add {TARGET_IP6}/64 dev lo 2>/dev/null || true",
    ]
    for cmd in cmds:
        try:
            subprocess.run(cmd, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass


# ==============================================================================
# SERVICIOS DE RESPUESTA EN EL TARGET
# ==============================================================================

class TargetServer:
    """Levanta los servicios de escucha en los puertos objetivo para completar handshakes."""
    def __init__(self):
        self.running = False
        self.sockets = []
        self.threads = []

    def start(self):
        self.running = True
        # HTTP (80, 8080), SSH (22), Exfil Sink (9000), UDP Sink (9999)
        tcp_services = [
            (80, b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<h1>FireNet Target</h1>"),
            (8080, b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}"),
            (22, b"SSH-2.0-OpenSSH_9.0 Ubuntu-Target\r\n"),
            (9000, b"ACK_EXFIL_STREAM_OK\n"),
        ]
        for port, resp in tcp_services:
            self._start_tcp(port, resp)
        self._start_udp(9999)
        time.sleep(0.3)

    def _start_tcp(self, port, response):
        for fam, addr in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
            try:
                s = socket.socket(fam, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((addr, port))
                s.listen(50)
                s.settimeout(0.5)
                self.sockets.append(s)

                def accept_loop(sock, data):
                    while self.running:
                        try:
                            client_sock, _ = sock.accept()
                            try:
                                client_sock.settimeout(0.5)
                                _ = client_sock.recv(1024)
                                if data:
                                    client_sock.sendall(data)
                            except Exception:
                                pass
                            finally:
                                client_sock.close()
                        except (socket.timeout, OSError):
                            continue
                        except Exception:
                            break

                t = threading.Thread(target=accept_loop, args=(s, response), daemon=True)
                t.start()
                self.threads.append(t)
            except Exception:
                pass

    def _start_udp(self, port):
        for fam, addr in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
            try:
                s = socket.socket(fam, socket.SOCK_DGRAM)
                s.bind((addr, port))
                s.settimeout(0.5)
                self.sockets.append(s)

                def udp_loop(sock):
                    while self.running:
                        try:
                            sock.recvfrom(4096)
                        except (socket.timeout, OSError):
                            continue
                        except Exception:
                            break

                t = threading.Thread(target=udp_loop, args=(s,), daemon=True)
                t.start()
                self.threads.append(t)
            except Exception:
                pass

    def stop(self):
        self.running = False
        for s in self.sockets:
            try:
                s.close()
            except Exception:
                pass
        self.sockets.clear()


# ==============================================================================
# GENERADORES DE TRÁFICO POR ESCENARIO
# ==============================================================================

def run_benign_traffic(count=20, ip_version=4):
    """Genera flujos legítimos del Cliente (HTTP, SSH, ICMP)."""
    target = TARGET_IP4 if ip_version == 4 else TARGET_IP6
    src_ip = CLIENT_IP4 if ip_version == 4 else CLIENT_IP6
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

    endpoints = ["/", "/index.html", "/api/v1/health", "/docs/about", "/images/logo.png"]
    for i in range(count):
        service = random.choice(["http", "http_alt", "ssh", "ping"])
        try:
            if service in ["http", "http_alt"]:
                port = 80 if service == "http" else 8080
                with socket.socket(family, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((src_ip, 0))
                    s.connect((target, port))
                    ep = random.choice(endpoints)
                    req = f"GET {ep} HTTP/1.1\r\nHost: target\r\nUser-Agent: Client-Agent\r\nConnection: close\r\n\r\n"
                    s.sendall(req.encode("utf-8"))
                    _ = s.recv(1024)
            elif service == "ssh":
                with socket.socket(family, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((src_ip, 0))
                    s.connect((target, 22))
                    _ = s.recv(128)
                    s.sendall(b"SSH-2.0-LegitimateClient_1.0\r\n")
                    time.sleep(0.01)
            elif service == "ping":
                with socket.socket(family, socket.SOCK_DGRAM) as s:
                    s.bind((src_ip, 0))
                    s.sendto(b"ICMP_PING_PAYLOAD", (target, 9999))
        except Exception:
            pass
        time.sleep(random.uniform(0.01, 0.04))


def run_attack_scan(ip_version=4, ports=None):
    """E1: Escaneo de puertos del atacante."""
    target = TARGET_IP4 if ip_version == 4 else TARGET_IP6
    src_ip = ATTACKER_IP4 if ip_version == 4 else ATTACKER_IP6
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

    if ports is None:
        ports = list(range(20, 110)) + [443, 8080, 8443, 9000, 9999]

    for port in ports:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(0.06)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((src_ip, 0))
                s.connect_ex((target, port))
        except Exception:
            pass
        time.sleep(0.005)


def run_attack_bruteforce(ip_version=4, attempts=40, target_port=22):
    """E2: Fuerza bruta de contraseñas contra SSH o HTTP."""
    target = TARGET_IP4 if ip_version == 4 else TARGET_IP6
    src_ip = ATTACKER_IP4 if ip_version == 4 else ATTACKER_IP6
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

    passwords = ["admin", "root", "123456", "password", "toor", "cisco", "supersecret", "pass123"]
    for i in range(attempts):
        pwd = passwords[i % len(passwords)]
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((src_ip, 0))
                s.connect((target, target_port))
                if target_port == 22:
                    _ = s.recv(64)
                    s.sendall(f"USER root PASS {pwd}\r\n".encode("utf-8"))
                else:
                    auth_req = f"POST /login HTTP/1.1\r\nHost: target\r\nContent-Length: 20\r\n\r\nu=root&p={pwd}"
                    s.sendall(auth_req.encode("utf-8"))
        except Exception:
            pass
        time.sleep(0.01)


def run_attack_ddos(ip_version=4, packets=300, mode="udp"):
    """E3: Inundación UDP o TCP a alta tasa."""
    target = TARGET_IP4 if ip_version == 4 else TARGET_IP6
    src_ip = ATTACKER_IP4 if ip_version == 4 else ATTACKER_IP6
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

    payload = b"DDoS_FLOOD_VOLUMETRIC_PAYLOAD_" * 16
    if mode == "udp":
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.bind((src_ip, 0))
                for _ in range(packets):
                    s.sendto(payload, (target, random.choice([80, 443, 9999, 53])))
        except Exception:
            pass
    else:
        for _ in range(packets):
            try:
                with socket.socket(family, socket.SOCK_STREAM) as s:
                    s.setblocking(False)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((src_ip, 0))
                    s.connect_ex((target, 80))
            except Exception:
                pass


def run_attack_exfiltration(ip_version=4, bursts=15, chunk_size=8192):
    """E4: Transferencia continua masiva en ráfagas."""
    target = TARGET_IP4 if ip_version == 4 else TARGET_IP6
    src_ip = ATTACKER_IP4 if ip_version == 4 else ATTACKER_IP6
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

    chunk = b"EXFIL_DATA_BLOCK_" * (chunk_size // 17)
    for b in range(bursts):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((src_ip, 0))
                s.connect((target, 9000))
                s.sendall(f"CHUNK_{b}_".encode("utf-8") + chunk)
                _ = s.recv(128)
        except Exception:
            try:
                with socket.socket(family, socket.SOCK_DGRAM) as s:
                    s.bind((src_ip, 0))
                    s.sendto(chunk[:1024], (target, 9999))
            except Exception:
                pass
        time.sleep(0.02)


def run_attack_stealth_probe(ip_version=4, count=12):
    """E5: Sondeo espaciado a baja frecuencia."""
    target = TARGET_IP4 if ip_version == 4 else TARGET_IP6
    src_ip = ATTACKER_IP4 if ip_version == 4 else ATTACKER_IP6
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

    probe_ports = [21, 22, 25, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 9000]
    for i in range(min(count, len(probe_ports))):
        port = probe_ports[i]
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((src_ip, 0))
                s.connect_ex((target, port))
        except Exception:
            pass
        time.sleep(random.uniform(0.15, 0.35))


# ==============================================================================
# SINTETIZADOR DE TRÁFICO SCAPY PARA MUESTREO DE ALTA DIVERSIDAD
# ==============================================================================

def generate_synthetic_pcap_flows(run_id, scenario_id, count=60):
    """
    Genera trazas de paquetes Scapy con alta fidelidad y varianza estadística
    para asegurar cobertura exhaustiva de flujos y casos límite en cada escenario.
    """
    packets = []
    base_time = time.time() - random.uniform(50, 500)
    
    attacker_ip4, target_ip4, client_ip4 = ATTACKER_IP4, TARGET_IP4, CLIENT_IP4
    attacker_ip6, target_ip6, client_ip6 = ATTACKER_IP6, TARGET_IP6, CLIENT_IP6

    # Siempre incluir tráfico benigno de fondo
    num_benign = count if scenario_id == "E0" else max(10, count // 3)
    for _ in range(num_benign):
        is_v6 = random.choice([True, False])
        src_ip = client_ip6 if is_v6 else client_ip4
        dst_ip = target_ip6 if is_v6 else target_ip4
        sport = random.randint(30000, 65000)
        dport = random.choice([80, 8080, 443, 22, 53])
        proto = 6 if dport != 53 else 17
        
        flow_time = base_time + random.uniform(0, 30)
        num_pkts = random.randint(4, 25)
        pkt_len = random.randint(64, 1400)
        
        # Paquete de inicio (SYN)
        flags = "S" if proto == 6 else None
        ip_layer = IPv6(src=src_ip, dst=dst_ip) if is_v6 else IP(src=src_ip, dst=dst_ip)
        trans_layer = TCP(sport=sport, dport=dport, flags=flags) if proto == 6 else UDP(sport=sport, dport=dport)
        p1 = ip_layer / trans_layer / Raw(b"GET / HTTP/1.1\r\n\r\n")
        p1.time = flow_time
        packets.append(p1)

        # Respuesta (SYN-ACK / ACK)
        flags_resp = "SA" if proto == 6 else None
        ip_resp = IPv6(src=dst_ip, dst=src_ip) if is_v6 else IP(src=dst_ip, dst=src_ip)
        trans_resp = TCP(sport=dport, dport=sport, flags=flags_resp) if proto == 6 else UDP(sport=dport, dport=sport)
        p2 = ip_resp / trans_resp / Raw(b"HTTP/1.1 200 OK\r\n\r\n" + b"X" * (pkt_len // 2))
        p2.time = flow_time + random.uniform(0.005, 0.05)
        packets.append(p2)

        # Paquetes adicionales de transferencia
        for k in range(num_pkts - 2):
            fwd = (k % 2 == 0)
            ip_k = IPv6(src=src_ip if fwd else dst_ip, dst=dst_ip if fwd else src_ip) if is_v6 else IP(src=src_ip if fwd else dst_ip, dst=dst_ip if fwd else src_ip)
            t_k = TCP(sport=sport if fwd else dport, dport=dport if fwd else sport, flags="A") if proto == 6 else UDP(sport=sport if fwd else dport, dport=dport if fwd else sport)
            pk = ip_k / t_k / Raw(b"DATA" * (random.randint(10, 80)))
            pk.time = p2.time + (k + 1) * random.uniform(0.002, 0.04)
            packets.append(pk)

    # Tráfico de ataque según el escenario
    if scenario_id == "E1":  # Port Scan
        scan_ports = random.sample(range(1, 1024), min(count, 80))
        for p in scan_ports:
            is_v6 = random.choice([True, False])
            src_ip = attacker_ip6 if is_v6 else attacker_ip4
            dst_ip = target_ip6 if is_v6 else target_ip4
            sport = random.randint(30000, 65000)
            
            ip_layer = IPv6(src=src_ip, dst=dst_ip) if is_v6 else IP(src=src_ip, dst=dst_ip)
            p_scan = ip_layer / TCP(sport=sport, dport=p, flags="S")
            p_scan.time = base_time + random.uniform(0, 10)
            packets.append(p_scan)

            if p in [22, 80, 8080]:
                ip_resp = IPv6(src=dst_ip, dst=src_ip) if is_v6 else IP(src=dst_ip, dst=src_ip)
                p_resp = ip_resp / TCP(sport=p, dport=sport, flags="SA")
                p_resp.time = p_scan.time + 0.002
                packets.append(p_resp)

    elif scenario_id == "E2":  # Brute Force
        for _ in range(count):
            is_v6 = random.choice([True, False])
            src_ip = attacker_ip6 if is_v6 else attacker_ip4
            dst_ip = target_ip6 if is_v6 else target_ip4
            sport = random.randint(30000, 65000)
            dport = random.choice([22, 80, 8080])

            ip_layer = IPv6(src=src_ip, dst=dst_ip) if is_v6 else IP(src=src_ip, dst=dst_ip)
            p1 = ip_layer / TCP(sport=sport, dport=dport, flags="S")
            p1.time = base_time + random.uniform(0, 5)
            packets.append(p1)

            ip_resp = IPv6(src=dst_ip, dst=src_ip) if is_v6 else IP(src=dst_ip, dst=src_ip)
            p2 = ip_resp / TCP(sport=dport, dport=sport, flags="SA")
            p2.time = p1.time + 0.002
            packets.append(p2)

            p3 = ip_layer / TCP(sport=sport, dport=dport, flags="PA") / Raw(b"AUTH FAIL INVALID PASSWORD")
            p3.time = p2.time + 0.005
            packets.append(p3)

    elif scenario_id == "E3":  # DDoS Flood
        for _ in range(count * 3):
            is_v6 = random.choice([True, False])
            src_ip = attacker_ip6 if is_v6 else attacker_ip4
            dst_ip = target_ip6 if is_v6 else target_ip4
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 9999, 53])
            proto = random.choice([6, 17])

            ip_layer = IPv6(src=src_ip, dst=dst_ip) if is_v6 else IP(src=src_ip, dst=dst_ip)
            trans = TCP(sport=sport, dport=dport, flags="S") if proto == 6 else UDP(sport=sport, dport=dport)
            p_flood = ip_layer / trans / Raw(b"FLOOD" * 30)
            p_flood.time = base_time + random.uniform(0, 2)
            packets.append(p_flood)

    elif scenario_id == "E4":  # Exfiltration
        for _ in range(max(10, count // 2)):
            is_v6 = random.choice([True, False])
            src_ip = attacker_ip6 if is_v6 else attacker_ip4
            dst_ip = target_ip6 if is_v6 else target_ip4
            sport = random.randint(30000, 65000)
            dport = 9000

            ip_layer = IPv6(src=src_ip, dst=dst_ip) if is_v6 else IP(src=src_ip, dst=dst_ip)
            p1 = ip_layer / TCP(sport=sport, dport=dport, flags="S")
            p1.time = base_time + random.uniform(0, 15)
            packets.append(p1)

            ip_resp = IPv6(src=dst_ip, dst=src_ip) if is_v6 else IP(src=dst_ip, dst=src_ip)
            p2 = ip_resp / TCP(sport=dport, dport=sport, flags="SA")
            p2.time = p1.time + 0.003
            packets.append(p2)

            for b in range(random.randint(20, 50)):
                pb = ip_layer / TCP(sport=sport, dport=dport, flags="A") / Raw(b"MASSIVE_CONFIDENTIAL_EXFILTRATED_DATA_BLOB_" * 15)
                pb.time = p2.time + (b + 1) * 0.005
                packets.append(pb)

    elif scenario_id == "E5":  # Stealth Probe
        ports_probe = [21, 22, 25, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 9000]
        for p in ports_probe[:min(count, len(ports_probe))]:
            is_v6 = random.choice([True, False])
            src_ip = attacker_ip6 if is_v6 else attacker_ip4
            dst_ip = target_ip6 if is_v6 else target_ip4
            sport = random.randint(30000, 65000)

            ip_layer = IPv6(src=src_ip, dst=dst_ip) if is_v6 else IP(src=src_ip, dst=dst_ip)
            p_probe = ip_layer / TCP(sport=sport, dport=p, flags="S")
            p_probe.time = base_time + random.uniform(0, 40)
            packets.append(p_probe)

    # Ordenar paquetes cronológicamente
    packets.sort(key=lambda x: getattr(x, 'time', 0))
    return packets


# ==============================================================================
# EJECUTOR PRINCIPAL DE RECOLECCIÓN
# ==============================================================================

def execute_dataset_collection():
    print("=" * 70)
    print(" FIRENET-AI: RECOLECCIÓN INTEGRAL DE DATASET (FASE 2: DÍA 3)")
    print("=" * 70)
    print(f" [*] Directorio crudo PCAP : {RAW_DIR}")
    print(f" [*] Archivo final CSV     : {PROCESSED_CSV}")
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_CSV.parent.mkdir(parents=True, exist_ok=True)

    # 1. Configurar interfaces
    configure_network_interfaces()

    # 2. Iniciar servidor Target
    target_server = TargetServer()
    target_server.start()
    print("[+] Servidor Target multisuite iniciado (80, 8080, 22, 9000, 9999).")

    # Si el CSV existe pero está vacío o sólo con cabecera, lo reiniciamos limpio
    if PROCESSED_CSV.exists():
        PROCESSED_CSV.unlink()

    matrix_scenarios = [
        # (scenario_id, num_runs, is_synthetic_boost)
        ("E0", 8, True),   # Benigno baseline amplio
        ("E1", 6, True),   # Escaneo de puertos
        ("E2", 6, True),   # Fuerza bruta
        ("E3", 6, True),   # Inundación / DDoS
        ("E4", 6, True),   # Exfiltración de datos
        ("E5", 6, True),   # Escaneo sigiloso
    ]

    total_runs = sum(runs for _, runs, _ in matrix_scenarios)
    current_run_idx = 0

    for scenario_id, num_runs, synth_boost in matrix_scenarios:
        for r in range(1, num_runs + 1):
            current_run_idx += 1
            run_id = f"RUN_{scenario_id}_{r:02d}"
            pcap_path = RAW_DIR / f"{scenario_id}_{run_id}.pcap"
            print(f"\n---> [{current_run_idx}/{total_runs}] Ejecutando Corrida {run_id} ({scenario_id})...")

            collector = DatasetCollector(
                scenario_id=scenario_id,
                label=0 if scenario_id == "E0" else 1,
                run_id=run_id,
                output_path=str(PROCESSED_CSV),
                window_seconds=2.0,
                save_pcap=str(pcap_path)
            )

            # A) Tráfico en tiempo real vía sockets en la interfaz
            ip_ver = 6 if (r % 2 == 0) else 4

            # Tráfico benigno recurrente
            t_benign = threading.Thread(
                target=run_benign_traffic,
                kwargs={"count": 15, "ip_version": ip_ver},
                daemon=True
            )
            t_benign.start()

            # Tráfico de escenario si no es puramente E0
            if scenario_id == "E1":
                run_attack_scan(ip_version=ip_ver)
            elif scenario_id == "E2":
                run_attack_bruteforce(ip_version=ip_ver, attempts=30)
            elif scenario_id == "E3":
                run_attack_ddos(ip_version=ip_ver, packets=250, mode="udp" if r % 2 == 1 else "syn")
            elif scenario_id == "E4":
                run_attack_exfiltration(ip_version=ip_ver, bursts=12)
            elif scenario_id == "E5":
                run_attack_stealth_probe(ip_version=ip_ver, count=10)

            t_benign.join(timeout=2.0)

            # B) Sintetizador de alta fidelidad Scapy para expandir la cobertura estadística
            if synth_boost:
                extra_pkts = generate_synthetic_pcap_flows(run_id, scenario_id, count=75)
                for pkt in extra_pkts:
                    collector.process_packet(pkt)

            # Flush de flujos hacia CSV y cierre de PCAP
            collector.flush_flows(force_all=True)
            print(f"     [✓] Finalizada {run_id}. Total paquetes procesados: {collector.total_packets_seen}")

    target_server.stop()
    print("\n" + "=" * 70)
    print(" RECOLECCIÓN DE DATASET COMPLETADA EXITOSAMENTE")
    print("=" * 70)

    # Validar estadísticas del dataset recolectado
    try:
        import pandas as pd
        df = pd.read_csv(PROCESSED_CSV)
        print("\n=== RESUMEN ESTADÍSTICO DEL DATASET RECOLECTADO ===")
        print(f"Total de flujos registrados : {len(df)}")
        print("\nDistribución por Escenario:")
        print(df['scenario_id'].value_counts())
        print("\nDistribución de Etiquetas (0=Benigno, 1=Ataque):")
        print(df['label'].value_counts(normalize=True).round(4) * 100)
        print("\nDistribución por Versión IP:")
        print(df['ip_version'].value_counts())
        print("\nDistribución por Protocolo (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6):")
        print(df['protocol'].value_counts())
        print("==================================================")
    except Exception as e:
        print(f"[*] Verificación estadística: {e}")


if __name__ == "__main__":
    execute_dataset_collection()
