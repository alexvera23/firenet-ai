#!/usr/bin/env python3
"""
FireNet-AI - Generador de Tráfico y Escenarios de Ataque (Fase 2)
Implementa la simulación de escenarios E0 a E5 conforme a docs/ROADMAP.md:
  - E0: Tráfico Benigno (HTTP GET, SSH legítimo, ICMP ping)
  - E1: Escaneo de Puertos (TCP Connect / SYN Scan en rangos amplios)
  - E2: Fuerza Bruta (Ráfaga de intentos de autenticación en SSH/HTTP)
  - E3: DDoS Controlado (Inundación UDP/TCP a alta tasa de paquetes)
  - E4: Exfiltración de Datos (Transferencia masiva continua en ráfagas)
  - E5: Escaneo Sigiloso / Stealth Probe (Sondeo espaciado de baja frecuencia)
  - Modo Servidor (--server): Respondedor multisuite en el nodo Target
"""

import time
import socket
import argparse
import random
import threading
import select
import sys

DEFAULT_TARGET_IP4 = "10.0.2.10"
DEFAULT_TARGET_IP6 = "fd00:2::10"

# Puertos comúnmente abiertos/escaneados
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080, 3306, 5432, 6379, 8443, 9000]


# ==============================================================================
# ESCENARIOS DE TRÁFICO (CLIENTE / ATACANTE)
# ==============================================================================

def traffic_benign(target, ip_version=4, count=25, delay_range=(0.05, 0.2), source_ip=None):
    """E0: Tráfico Benigno mixto (HTTP GET, SSH handshake legítimo, ICMP)"""
    print(f"[*] [E0] Generando Tráfico Benigno hacia {target} (IPv{ip_version}) desde {source_ip or 'auto'}...")
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

    for i in range(count):
        service_choice = random.choice(["http", "http_alt", "ssh", "ping"])
        try:
            if service_choice in ["http", "http_alt"]:
                port = 80 if service_choice == "http" else 8080
                with socket.socket(family, socket.SOCK_STREAM) as s:
                    s.settimeout(1.5)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if source_ip:
                        s.bind((source_ip, 0))
                    s.connect((target, port))
                    request = f"GET /page_{i}.html HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0 (FireNet-Client)\r\nConnection: close\r\n\r\n"
                    s.sendall(request.encode("utf-8"))
                    # Leer respuesta
                    s.recv(1024)
            elif service_choice == "ssh":
                with socket.socket(family, socket.SOCK_STREAM) as s:
                    s.settimeout(1.5)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if source_ip:
                        s.bind((source_ip, 0))
                    s.connect((target, 22))
                    # Recibir banner de SSH y responder con identificación de cliente legítimo
                    banner = s.recv(256)
                    s.sendall(b"SSH-2.0-OpenSSH_9.0 legitimate-client\r\n")
                    time.sleep(0.02)
            elif service_choice == "ping":
                # Datagrama ICMP simulado vía raw socket o UDP ping fallback
                with socket.socket(family, socket.SOCK_DGRAM) as s:
                    if source_ip:
                        s.bind((source_ip, 0))
                    s.sendto(b"FIRENET_PING_E0", (target, 9999))
        except Exception:
            pass

        time.sleep(random.uniform(*delay_range))

    print(f"[+] [E0] Tráfico benigno completado ({count} solicitudes).")


def attack_scan(target, ip_version=4, ports=None, source_ip=None):
    """E1: Escaneo de Puertos (Simulación de nmap -sS / -sT)"""
    if ports is None:
        # Rango representativo de puertos
        ports = list(range(20, 105)) + [443, 8080, 8443, 9000, 9999, 27017]
    print(f"[*] [E1] Ejecutando Escaneo de Puertos ({len(ports)} puertos) hacia {target} desde {source_ip or 'auto'}...")
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

    open_ports = []
    for port in ports:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(0.08)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if source_ip:
                    s.bind((source_ip, 0))
                res = s.connect_ex((target, port))
                if res == 0:
                    open_ports.append(port)
        except Exception:
            pass
        time.sleep(0.01)

    print(f"[+] [E1] Escaneo finalizado. Puertos detectados: {open_ports}")


def attack_bruteforce(target, ip_version=4, attempts=50, target_port=22, source_ip=None):
    """E2: Fuerza Bruta / Credential Stuffing (Simulación de Hydra)"""
    print(f"[*] [E2] Ejecutando Fuerza Bruta contra puerto {target_port} en {target} ({attempts} intentos) desde {source_ip or 'auto'}...")
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

    passwords = ["admin", "123456", "root", "password", "toor", "cisco", "secret"]
    for i in range(attempts):
        pwd = passwords[i % len(passwords)]
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(0.4)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if source_ip:
                    s.bind((source_ip, 0))
                s.connect((target, target_port))
                if target_port == 22:
                    s.recv(128)
                    s.sendall(f"USER root PASS {pwd}\r\n".encode("utf-8"))
                else:
                    auth_req = f"POST /login HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 25\r\n\r\nuser=admin&pass={pwd}"
                    s.sendall(auth_req.encode("utf-8"))
        except Exception:
            pass
        time.sleep(0.02)

    print(f"[+] [E2] Ataque de fuerza bruta completado.")


def attack_ddos(target, ip_version=4, packets=500, mode="udp", source_ip=None):
    """E3: DDoS Controlado / Inundación (Simulación de hping3 --flood)"""
    print(f"[*] [E3] Ejecutando DDoS / Inundación ({mode.upper()}) hacia {target} ({packets} paquetes) desde {source_ip or 'auto'}...")
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

    payload = b"A" * 512
    if mode == "udp":
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            if source_ip:
                s.bind((source_ip, 0))
            for _ in range(packets):
                dport = random.choice([80, 443, 9999, 53])
                s.sendto(payload, (target, dport))
    else:
        # Ráfaga TCP Syn
        for _ in range(packets):
            try:
                with socket.socket(family, socket.SOCK_STREAM) as s:
                    s.setblocking(False)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if source_ip:
                        s.bind((source_ip, 0))
                    s.connect_ex((target, 80))
            except Exception:
                pass

    print(f"[+] [E3] Inundación DDoS completada.")


def attack_exfiltration(target, ip_version=4, bursts=15, chunk_size=8192, target_port=9000, source_ip=None):
    """E4: Exfiltración Masiva de Datos en ráfagas (Simulación de Netcat Data Exfiltration)"""
    print(f"[*] [E4] Ejecutando Exfiltración masiva continua hacia {target}:{target_port} ({bursts} ráfagas x {chunk_size} bytes) desde {source_ip or 'auto'}...")
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

    dummy_data = b"D" * chunk_size
    for b in range(bursts):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if source_ip:
                    s.bind((source_ip, 0))
                s.connect((target, target_port))
                # Enviar bloque de datos continuo simulando archivo robado
                header = f"EXFIL_STREAM_ID_{b}\n".encode("utf-8")
                s.sendall(header + dummy_data)
                time.sleep(0.03)
        except Exception:
            # Si el puerto no acepta stream continuo, enviar ráfaga por UDP
            try:
                with socket.socket(family, socket.SOCK_DGRAM) as s:
                    if source_ip:
                        s.bind((source_ip, 0))
                    s.sendto(dummy_data[:1024], (target, 9999))
            except Exception:
                pass
        time.sleep(0.05)

    print(f"[+] [E4] Exfiltración de datos completada.")


def attack_stealth_probe(target, ip_version=4, count=15, source_ip=None):
    """E5: Escaneo Sigiloso / Low-and-Slow Probe (Para evaluación de generalización ML)"""
    print(f"[*] [E5] Ejecutando Sondeo Sigiloso (Low-and-Slow) hacia {target} ({count} sondas) desde {source_ip or 'auto'}...")
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

    probe_ports = [21, 22, 25, 80, 110, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 9000]
    for i in range(min(count, len(probe_ports))):
        port = probe_ports[i]
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if source_ip:
                    s.bind((source_ip, 0))
                s.connect_ex((target, port))
        except Exception:
            pass
        # Intervalo para evadir detección trivial por tasa de paquetes (PPS)
        time.sleep(random.uniform(0.3, 0.7))

    print(f"[+] [E5] Sondeo sigiloso completado.")


# ==============================================================================
# SERVIDOR MULTIPUERTO DE RESPUESTA EN EL TARGET (--server)
# ==============================================================================

def run_tcp_service(port, banner_or_resp):
    """Servicio TCP básico para responder y completar apretones de manos (handshakes)"""
    for family in [socket.AF_INET, socket.AF_INET6]:
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bind_addr = "0.0.0.0" if family == socket.AF_INET else "::"
            s.bind((bind_addr, port))
            s.listen(10)
            s.setblocking(False)

            def handle_connections(sock, response_data, p):
                while True:
                    try:
                        readable, _, _ = select.select([sock], [], [], 1.0)
                        if readable:
                            client_sock, _ = sock.accept()
                            try:
                                client_sock.settimeout(1.0)
                                req = client_sock.recv(4096)
                                if response_data:
                                    client_sock.sendall(response_data)
                            except Exception:
                                pass
                            finally:
                                client_sock.close()
                    except Exception:
                        break

            t = threading.Thread(target=handle_connections, args=(s, banner_or_resp, port), daemon=True)
            t.start()
        except Exception:
            pass


def run_udp_sink(port=9999):
    """Receptor UDP para sinks de inundación y pings"""
    for family in [socket.AF_INET, socket.AF_INET6]:
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            bind_addr = "0.0.0.0" if family == socket.AF_INET else "::"
            s.bind((bind_addr, port))

            def listen_udp(sock):
                while True:
                    try:
                        sock.recvfrom(4096)
                    except Exception:
                        break

            t = threading.Thread(target=listen_udp, args=(s,), daemon=True)
            t.start()
        except Exception:
            pass


def start_target_server():
    """Inicia todos los servicios del nodo Target (HTTP, SSH, Exfiltración, UDP Sink)"""
    print("=" * 60)
    print(" FireNet-AI Target Responder Server iniciado")
    print("=" * 60)
    print(" [*] Puerto 80   : HTTP Server (200 OK)")
    print(" [*] Puerto 8080 : HTTP Alternate Server")
    print(" [*] Puerto 22   : SSH Emulated Banner")
    print(" [*] Puerto 9000 : Data Exfiltration Sink")
    print(" [*] Puerto 9999 : UDP Flood Sink")
    print(" Presione Ctrl+C para detener.")
    print("=" * 60)

    http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 42\r\nConnection: close\r\n\r\n<html><body>FireNet-AI Target</body></html>\n"
    ssh_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
    sink_ack = b"ACK_EXFIL_RECEIVED\n"

    run_tcp_service(80, http_resp)
    run_tcp_service(8080, http_resp)
    run_tcp_service(22, ssh_banner)
    run_tcp_service(9000, sink_ack)
    run_udp_sink(9999)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Servidor Target detenido.")


# ==============================================================================
# ENTRADA PRINCIPAL
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Generador de Tráfico y Escenarios FireNet-AI")
    parser.add_argument("--scenario", "-s", choices=["E0", "E1", "E2", "E3", "E4", "E5"], default="E0",
                        help="Escenario a ejecutar: E0=Benigno, E1=Scan, E2=Bruteforce, E3=DDoS, E4=Exfiltration, E5=Stealth")
    parser.add_argument("--ip", type=int, choices=[4, 6], default=4,
                        help="Versión de protocolo IP a utilizar (4 o 6)")
    parser.add_argument("--source-ip", default=None,
                        help="IP de origen a asociar al socket (ej. 10.0.1.10 o 10.0.3.10)")
    parser.add_argument("--target", "-t", default=None,
                        help="IP de destino (por defecto: 10.0.2.10 para IPv4, fd00:2::10 para IPv6)")
    parser.add_argument("--count", "-c", type=int, default=None,
                        help="Cantidad de solicitudes, paquetes o intentos según el escenario")
    parser.add_argument("--server", action="store_true",
                        help="Ejecutar en modo Servidor Respondedor multisuite en el nodo Target")

    args = parser.parse_args()

    if args.server:
        start_target_server()
        return

    # Determinar IP de destino
    if args.target:
        target_ip = args.target
    else:
        target_ip = DEFAULT_TARGET_IP4 if args.ip == 4 else DEFAULT_TARGET_IP6

    if args.scenario == "E0":
        count = args.count or 25
        traffic_benign(target_ip, args.ip, count=count, source_ip=args.source_ip)
    elif args.scenario == "E1":
        attack_scan(target_ip, args.ip, source_ip=args.source_ip)
    elif args.scenario == "E2":
        attempts = args.count or 50
        attack_bruteforce(target_ip, args.ip, attempts=attempts, source_ip=args.source_ip)
    elif args.scenario == "E3":
        packets = args.count or 500
        attack_ddos(target_ip, args.ip, packets=packets, source_ip=args.source_ip)
    elif args.scenario == "E4":
        bursts = args.count or 20
        attack_exfiltration(target_ip, args.ip, bursts=bursts, source_ip=args.source_ip)
    elif args.scenario == "E5":
        count = args.count or 15
        attack_stealth_probe(target_ip, args.ip, count=count, source_ip=args.source_ip)


if __name__ == "__main__":
    main()
