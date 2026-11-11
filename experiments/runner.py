#!/usr/bin/env python3
"""
FireNet-AI - Harness de Ejecución Experimental (Fase 4)
Compara Línea Base Estática (sin pipeline) vs. FireNet-AI Adaptativo (con pipeline).
Uso: python experiments/runner.py {baseline|adaptive} [--tag NOMBRE]
"""

import os
import re
import json
import time
import argparse
import subprocess
from datetime import datetime

import psutil

RESULTS_DIR = "experiments/runs"
TARGET_IP = "10.0.2.10"
PIPELINE_MATCH = "src/pipeline.py"
NFT_CHAIN = ["inet", "firenet_table", "dynamic_rules"]
SETTLE_SEC = 1.0
COOLDOWN_WAIT = 6  # > cooldown_seconds (5) del PolicyEngine
POLL_SEC = 0.25

SCENARIOS = [
    ("E0", "Benign", 0),
    ("E1", "PortScan", 1),
    ("E2", "BruteForce", 1),
    ("E3", "DDoS", 1),
]

PROBE_CODE = (
    "import socket,sys\n"
    "s=socket.socket(); s.settimeout(1.5)\n"
    "try:\n"
    "    s.connect((sys.argv[1], int(sys.argv[2]))); print('open')\n"
    "except socket.timeout:\n"
    "    print('timeout')\n"
    "except OSError:\n"
    "    print('refused')\n"
)


def ns_exec(ns, *cmd):
    return ["sudo", "ip", "netns", "exec", ns, *cmd]


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def get_system_metrics():
    cpu = psutil.cpu_percent(interval=0.2)
    ram = psutil.virtual_memory().used / (1024 * 1024)
    return cpu, round(ram, 2)


def pipeline_running():
    for p in psutil.process_iter(["cmdline"]):
        try:
            if any(PIPELINE_MATCH in a for a in (p.info["cmdline"] or [])):
                return True
        except psutil.Error:
            continue
    return False


def list_rules():
    """Lee las reglas de dynamic_rules (nft -j) y extrae id, src, proto y dport."""
    res = run(ns_exec("gateway", "nft", "-j", "list", "chain", *NFT_CHAIN))
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return []

    rules = []
    for item in data.get("nftables", []):
        r = item.get("rule")
        if not r:
            continue
        info = {"handle": r.get("handle"), "comment": r.get("comment", ""),
                "src": None, "proto": None, "dport": None}
        m = re.search(r"firenet_id=(\S+)", info["comment"])
        info["rule_id"] = m.group(1) if m else None
        for e in r.get("expr", []):
            match = e.get("match")
            if not match:
                continue
            left = match.get("left", {}).get("payload", {})
            if left.get("field") == "saddr":
                info["src"] = match.get("right")
            elif left.get("field") == "dport":
                info["dport"] = match.get("right")
                info["proto"] = left.get("protocol")
        rules.append(info)
    return rules


def flush_rules():
    run(ns_exec("gateway", "nft", "flush", "chain", *NFT_CHAIN))
    time.sleep(COOLDOWN_WAIT)


def measure_ping_latency(ns="client", count=5):
    """RTT real (p50/p95) y pérdida, desde `ns` hacia el target."""
    res = run(ns_exec(ns, "ping", "-c", str(count), "-i", "0.2", "-W", "1", TARGET_IP))
    times = sorted(float(t) for t in re.findall(r"time=([\d.]+) ms", res.stdout))
    if not times:
        return {"p50": None, "p95": None, "loss_pct": 100.0, "status": "failed"}
    p50 = times[len(times) // 2]
    p95 = times[min(len(times) - 1, int(len(times) * 0.95))]
    return {"p50": p50, "p95": p95,
            "loss_pct": round(100 * (count - len(times)) / count, 1),
            "status": "success"}


def probe_drop(rules):
    """Desde attacker: timeout en el puerto de la regla => el drop funciona.
    Devuelve True/False, o None si ninguna regla permite probar (sin dport/TCP)."""
    results = []
    for r in rules:
        if r["proto"] == "tcp" and r["dport"]:
            out = run(ns_exec("attacker", "./.venv/bin/python3", "-c", PROBE_CODE,
                              TARGET_IP, str(r["dport"]))).stdout.strip()
            results.append(out == "timeout")
    return any(results) if results else None


def run_scenario(sid, name, label):
    print(f"\n[*] Escenario {sid} ({name})...")
    flush_rules()
    cpu0, ram0 = get_system_metrics()
    lat_pre = measure_ping_latency()

    ns_src = "attacker" if label == 1 else "client"
    gen_cmd = ns_exec(ns_src, "./.venv/bin/python3", "lab/traffic-scenarios/generator.py",
                      "--scenario", sid, "--ip", "4")

    t0 = time.time()
    gen = subprocess.Popen(gen_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time_to_block = None
    while gen.poll() is None:
        if time_to_block is None and list_rules():
            time_to_block = round(time.time() - t0, 3)
        time.sleep(POLL_SEC)
    duration = round(time.time() - t0, 3)

    time.sleep(SETTLE_SEC)
    rules = list_rules()
    if time_to_block is None and rules:
        time_to_block = round(time.time() - t0, 3)  # apareció después del generador

    lat_post = measure_ping_latency()
    cpu1, ram1 = get_system_metrics()

    rule_installed = len(rules) > 0
    traffic_blocked = probe_drop(rules) if (label == 1 and rule_installed) else None

    metrics = {
        "scenario": sid,
        "target_label": label,
        "duration_sec": duration,
        "time_to_block_sec": time_to_block,
        "dynamic_rules_active": len(rules),
        "rule_installed": rule_installed,
        "traffic_blocked": traffic_blocked,
        "false_positive": (rule_installed if label == 0 else None),
        "latency_pre_ms": lat_pre["p50"],
        "latency_post_ms": lat_post["p50"],
        "latency_post_p95_ms": lat_post["p95"],
        "client_loss_post_pct": lat_post["loss_pct"],
        "cpu_avg_pct": round((cpu0 + cpu1) / 2, 2),
        "ram_avg_mb": round((ram0 + ram1) / 2, 2),
        "rules": [{k: r[k] for k in ("rule_id", "src", "proto", "dport")} for r in rules],
    }
    print(f"[+] {sid}: reglas={len(rules)} | t_bloqueo={time_to_block}s | "
          f"drop_confirmado={traffic_blocked} | FP={metrics['false_positive']}")
    return metrics


def run_experiment_matrix(mode="adaptive", tag=None):
    running = pipeline_running()
    if mode == "adaptive" and not running:
        raise SystemExit("[!] Modo adaptive: el pipeline no está corriendo en gateway.")
    if mode == "baseline" and running:
        raise SystemExit("[!] Modo baseline: detén src/pipeline.py antes de correr.")

    label = f"{mode}_{tag}" if tag else mode
    print(f"\n{'=' * 50}\n[*] Campaña Experimental - {label.upper()}\n{'=' * 50}")

    results = {"timestamp": datetime.now().isoformat(), "mode": mode, "tag": tag, "scenarios": {}}
    for sid, name, lbl in SCENARIOS:
        results["scenarios"][sid] = run_scenario(sid, name, lbl)

    flush_rules()
    os.makedirs(RESULTS_DIR, exist_ok=True)
    out = os.path.join(RESULTS_DIR, f"exp_{label}_{int(time.time())}.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Resultados guardados en: {out}")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", nargs="?", default="adaptive", choices=["baseline", "adaptive"])
    ap.add_argument("--tag", default=None, help="Etiqueta de variante (para ablation)")
    args = ap.parse_args()
    run_experiment_matrix(args.mode, args.tag)