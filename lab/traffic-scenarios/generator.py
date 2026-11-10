#!/usr/bin/env python3
import time
import socket
import argparse
import random

TARGET_IP4 = "192.168.20.2"
TARGET_IP6 = "fd00:20::2"

def traffic_benign(ip_version=4, count=20):
    print(f"[*] Ejecutando E0 (Tráfico Benigno IPv{ip_version})...")
    target = TARGET_IP4 if ip_version == 4 else TARGET_IP6
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6
    
    for i in range(count):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                # Intento de conexión simulación HTTP/DNS/SSH benigno
                s.connect_ex((target, 80))
                time.sleep(random.uniform(0.1, 0.4))
        except Exception:
            pass
    print("[+] Tráfico benigno completado.")

def attack_scan(ip_version=4):
    print(f"[*] Ejecutando E1 (Escaneo de Puertos IPv{ip_version})...")
    target = TARGET_IP4 if ip_version == 4 else TARGET_IP6
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6
    
    # Escaneo rápido de múltiples puertos (comportamiento de nmap)
    ports = [21, 22, 23, 25, 80, 443, 8080, 3306, 5432, 27017]
    for port in ports:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(0.05)
            s.connect_ex((target, port))
            time.sleep(0.02)
    print("[+] Escaneo completado.")

def attack_bruteforce(ip_version=4, attempts=30):
    print(f"[*] Ejecutando E2 (Fuerza Bruta IPv{ip_version})...")
    target = TARGET_IP4 if ip_version == 4 else TARGET_IP6
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6
    
    # Reintentos continuos sobre un mismo puerto (SSH/FTP)
    for _ in range(attempts):
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            s.connect_ex((target, 22))
            time.sleep(0.05)
    print("[+] Fuerza bruta completada.")

def attack_ddos(ip_version=4, packets=100):
    print(f"[*] Ejecutando E3 (DDoS / Ráfaga IPv{ip_version})...")
    target = TARGET_IP4 if ip_version == 4 else TARGET_IP6
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6
    
    # Ráfaga UDP sin espera entre paquetes
    for _ in range(packets):
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.sendto(b"X" * 64, (target, 9999))
    print("[+] DDoS ráfaga completado.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generador de Tráfico FireNet-AI")
    parser.add_argument("--scenario", choices=["E0", "E1", "E2", "E3"], default="E0")
    parser.add_argument("--ip", type=int, choices=[4, 6], default=4)
    args = parser.parse_args()

    if args.scenario == "E0":
        traffic_benign(args.ip)
    elif args.scenario == "E1":
        attack_scan(args.ip)
    elif args.scenario == "E2":
        attack_bruteforce(args.ip)
    elif args.scenario == "E3":
        attack_ddos(args.ip)