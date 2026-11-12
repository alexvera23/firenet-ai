#!/usr/bin/env python3
"""
FireNet-AI - Flujo de Inferencia en Tiempo Real (Live Inference Pipeline)
Conforme a Fase 3 (PROMPT1 y ROADMAP):
  - Integra captura en tiempo real (lógica de extracción de características de sniffer.py).
  - Inferencia mediante modelo serializado (firenet_best_model.pkl y model_metadata.json).
  - Evaluación y toma de decisiones con PolicyEngine.
  - Aplicación de medidas de contención reactivas con NftablesExecutor.
  - Registro estructurado en formato JSONL en logs/audit.jsonl con los campos:
    timestamp, run_id, flow_id, model_version, score, policy_action, rule_id, ttl, apply_status.
  - Soporte de ejecución tanto en vivo (live sniffing en netns) como offline (PCAP replay).
"""

import os
import sys
import json
import time
import argparse
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Union

# Asegurar importaciones relativas desde la raíz del proyecto
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import pandas as pd
import numpy as np

from src.features.extractor import FlowExtractor
from src.models import DynamicRule
from src.policy.engine import PolicyEngine, PolicyAction, PolicyDecision
from src.firewall.executor import NftablesExecutor

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
except ImportError:
    sniff = None
    IP = IPv6 = TCP = UDP = ICMP = None

logger = logging.getLogger("FireNetPipeline")


class LiveInferencePipeline:
    def __init__(
        self,
        model_path: Union[str, Path] = PROJECT_ROOT / "models" / "firenet_best_model.pkl",
        metadata_path: Union[str, Path] = PROJECT_ROOT / "models" / "model_metadata.json",
        audit_log_path: Union[str, Path] = PROJECT_ROOT / "logs" / "audit.jsonl",
        netns: Optional[str] = None,
        table: str = "firenet",
        family: str = "inet",
        chain: str = "dynamic_rules",
        dry_run: bool = False,
        use_unshare: bool = False,
        run_id: Optional[str] = None,
        window_seconds: float = 2.0,
        min_score: float = 0.85,
        policy_config: Optional[Dict[str, Any]] = None,
        auto_expire: bool = True,
    ):
        self.model_path = Path(model_path)
        self.metadata_path = Path(metadata_path)
        self.audit_log_path = Path(audit_log_path)
        self.netns = netns
        self.dry_run = dry_run
        self.use_unshare = use_unshare
        self.run_id = run_id or f"RUN_LIVE_{int(time.time())}"
        self.window_seconds = window_seconds
        self.min_score = min_score

        # 1. Cargar artefacto del modelo y metadatos
        self.model, self.metadata = self._load_model_and_metadata()
        self.model_version = self.metadata.get("best_model", "MLP")
        self.feature_columns = self.metadata.get("features", [
            'ip_version', 'protocol', 'duration', 'packets', 'bytes',
            'pps', 'bps', 'pkts_fwd', 'pkts_rev', 'ratio_pkts',
            'mean_pkt_size', 'src_port', 'dst_port', 'syn_flag'
        ])

        # 2. Inicializar Motor de Políticas (Policy Engine)
        pol_cfg = dict(policy_config or {})
        if "min_score" not in pol_cfg:
            pol_cfg["min_score"] = self.min_score

        self.policy_engine = PolicyEngine(config=pol_cfg)

        # 3. Inicializar Ejecutor de Firewall (NftablesExecutor)
        self.executor = NftablesExecutor(
            table=table,
            family=family,
            chain=chain,
            netns=self.netns,
            dry_run=self.dry_run,
            use_unshare=self.use_unshare,
            auto_expire=auto_expire,
            on_expire_callback=self._on_rule_expired,
            on_revoke_callback=self._on_rule_revoked,
        )

        # 4. Inicializar Extractor de Características
        self.extractor = FlowExtractor(window_seconds=self.window_seconds)

        # 5. Asegurar directorio de auditoría
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

        # Métricas de ejecución
        self.evaluations_count = 0
        self.rules_applied_count = 0
        self.packets_processed = 0

    def _load_model_and_metadata(self):
        """Carga el modelo serializado y sus metadatos asociados."""
        if not self.model_path.exists():
            raise FileNotFoundError(f"Artefacto de modelo no encontrado en: {self.model_path}")

        model = joblib.load(self.model_path)

        metadata = {}
        if self.metadata_path.exists():
            with open(self.metadata_path, "r") as f:
                metadata = json.load(f)

        return model, metadata

    def _on_rule_expired(self, rule_id: str):
        """Notificación cuando una regla dinámica expira por TTL."""
        self.policy_engine.record_expired(rule_id)
        logger.info(f"[PIPELINE TTL] Regla {rule_id} expirada y registrada en PolicyEngine.")

    def _on_rule_revoked(self, rule_id: str):
        """Notificación cuando una regla dinámica es revocada."""
        self.policy_engine.record_revoked(rule_id)
        logger.info(f"[PIPELINE REVOKE] Regla {rule_id} revocada y registrada en PolicyEngine.")

    def parse_packet_metadata(self, packet) -> Optional[Dict[str, Any]]:
        """
        Extrae metadatos de un paquete de Scapy conforme a la lógica de sniffer.py.
        Descarta tráfico loopback, multicast local y mensajes NDP de IPv6.
        """
        if (packet.haslayer(ICMPv6ND_NS) or packet.haslayer(ICMPv6ND_NA) or 
            packet.haslayer(ICMPv6ND_RA) or packet.haslayer(ICMPv6ND_RS)):
            return None

        ip_version = 0
        src_ip, dst_ip = None, None
        protocol = 0
        src_port, dst_port = 0, 0

        if packet.haslayer(IP):
            ip_version = 4
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            if src_ip.startswith("127.") or dst_ip.startswith("127.") or dst_ip.startswith("224."):
                return None
        elif packet.haslayer(IPv6):
            ip_version = 6
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            protocol = packet[IPv6].nh
            if src_ip == "::1" or dst_ip.startswith("ff02::") or src_ip.startswith("fe80::"):
                return None
        else:
            return None

        if not src_ip or not dst_ip:
            return None

        # Capa de transporte y flags TCP
        tcp_flags = set()
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            raw_flags = packet[TCP].flags
            if raw_flags & 0x02: tcp_flags.add("SYN")
            if raw_flags & 0x10: tcp_flags.add("ACK")
            if raw_flags & 0x01: tcp_flags.add("FIN")
            if raw_flags & 0x04: tcp_flags.add("RST")
            if raw_flags & 0x08: tcp_flags.add("PSH")
            if raw_flags & 0x20: tcp_flags.add("URG")
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = 1
        elif packet.haslayer(ICMPv6EchoRequest) or packet.haslayer(ICMPv6EchoReply):
            protocol = 58

        return {
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

    def process_packet(self, packet):
        """Procesa un paquete de red en vivo, actualizando los flujos acumulados."""
        meta = self.parse_packet_metadata(packet)
        if not meta:
            return

        self.extractor.process_packet(meta)
        self.packets_processed += 1

        # Evaluar flujos expirados o listos para inferencia
        ready_flows = self.extractor.extract_features(force_all=False)
        for flow_id, feat in ready_flows:
            self.evaluate_flow(flow_id, feat)

    def evaluate_flow(self, flow_id: str, flow_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta la inferencia ML sobre el flujo, evalúa las políticas y aplica contención.
        Registra el evento de auditoría en audit.jsonl.
        """
        self.evaluations_count += 1
        eval_timestamp = time.time()

        # 1. Preparar vector de características para el modelo
        feature_dict = {}
        for col in self.feature_columns:
            feature_dict[col] = flow_features.get(col, 0)
        input_df = pd.DataFrame([feature_dict])

        # 2. Inferencia ML (probabilidad de ataque/malicioso)
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(input_df)[0]
            malicious_score = float(probs[1]) if len(probs) > 1 else float(probs[0])
        else:
            pred = self.model.predict(input_df)[0]
            malicious_score = 1.0 if pred == 1 else 0.0

        # 3. Construir clave de flujo para el evaluador de políticas
        src_ip = flow_features.get('initiator_ip') or flow_features.get('src_ip')
        dst_ip = flow_features.get('responder_ip') or flow_features.get('dst_ip')
        src_port = flow_features.get('src_port', 0)
        dst_port = flow_features.get('dst_port', 0)
        protocol = flow_features.get('protocol', 6)
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

        # 4. Evaluación en el Policy Engine
        decision = self.policy_engine.evaluate(
            flow_key=flow_key,
            score=malicious_score,
            flow_data=flow_features,
            current_time=eval_timestamp
        )

        # 5. Ejecución en Firewall si la acción es APPLY
        apply_status = "NOT_APPLIED"
        rule_id = None
        ttl_val = None

        if decision.action == PolicyAction.APPLY and decision.rule:
            rule = decision.rule
            rule_id = rule.rule_id
            ttl_val = rule.ttl

            success = self.executor.apply_rule(rule)
            if success:
                apply_status = "APPLIED"
                self.policy_engine.record_applied(rule, timestamp=eval_timestamp)
                self.rules_applied_count += 1
            else:
                apply_status = "FAILED"
        elif decision.action == PolicyAction.OBSERVE:
            apply_status = "SKIPPED"
        elif decision.action == PolicyAction.ALERT:
            apply_status = "ALERTED"

        # 6. Registro de Auditoría Estructurado JSONL
        # Campos requeridos por PROMPT1:
        # timestamp, run_id, flow_id, model_version, score, policy_action, rule_id, ttl, apply_status
        audit_entry = {
            "timestamp": eval_timestamp,
            "run_id": self.run_id,
            "flow_id": flow_id,
            "model_version": self.model_version,
            "score": round(malicious_score, 4),
            "policy_action": decision.action.value,
            "rule_id": rule_id,
            "ttl": ttl_val,
            "apply_status": apply_status,
            "reason": decision.reason,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        }

        self._write_audit_log(audit_entry)
        return audit_entry

    def _write_audit_log(self, record: Dict[str, Any]):
        """Escribe una línea JSON en el archivo logs/audit.jsonl."""
        try:
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.error(f"[AUDIT LOG ERROR] No se pudo escribir registro de auditoría: {e}")

    def process_pcap(self, pcap_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """
        Procesa un archivo de captura .pcap completo para análisis forense o validación experimental.
        """
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"Archivo PCAP no encontrado: {pcap_file}")

        if sniff is None:
            raise ImportError("Scapy es requerido para procesar archivos .pcap.")

        logger.info(f"[PIPELINE PCAP] Replay de captura: {pcap_file}")
        sniff(offline=str(pcap_file), prn=self.process_packet, store=0)

        # Forzar procesamiento de todos los flujos remanentes
        remaining_flows = self.extractor.extract_features(force_all=True)
        audit_results = []
        for flow_id, feat in remaining_flows:
            audit = self.evaluate_flow(flow_id, feat)
            audit_results.append(audit)

        logger.info(
            f"[PIPELINE PCAP COMPLETADO] Pkts={self.packets_processed} | "
            f"Flujos={self.evaluations_count} | Reglas={self.rules_applied_count}"
        )
        return audit_results

    def start_sniffing(
        self,
        interface: Optional[str] = None,
        bpf: str = "",
        timeout: int = 0
    ):
        """Inicia la captura de tráfico en tiempo real."""
        if sniff is None:
            raise ImportError("Scapy es requerido para captura en tiempo real.")

        # Asegurar tabla y cadena en nftables antes de iniciar
        self.executor.ensure_chain_exists()

        sniff_kwargs = {
            "prn": self.process_packet,
            "store": 0,
        }
        if interface:
            sniff_kwargs["iface"] = interface
        if bpf:
            sniff_kwargs["filter"] = bpf
        if timeout > 0:
            sniff_kwargs["timeout"] = timeout

        logger.info(
            f"[PIPELINE START] Interfaz: {interface or 'Any'} | "
            f"Netns: {self.netns or 'Host'} | Dry-Run: {self.dry_run}"
        )

        try:
            sniff(**sniff_kwargs)
        except KeyboardInterrupt:
            logger.info("[PIPELINE] Detención manual solicitada por el usuario.")
        finally:
            # Procesar últimos flujos en memoria
            remaining = self.extractor.extract_features(force_all=True)
            for flow_id, feat in remaining:
                self.evaluate_flow(flow_id, feat)
            logger.info(f"[PIPELINE STOP] Total paquetes={self.packets_processed}, Reglas={self.rules_applied_count}")


def main():
    parser = argparse.ArgumentParser(description="FireNet-AI Live Inference Pipeline")
    parser.add_argument("--interface", "-i", default=None,
                        help="Interfaz de red de captura (ej. veth-gw-c o any)")
    parser.add_argument("--pcap", default=None,
                        help="Archivo .pcap para procesamiento offline")
    parser.add_argument("--netns", default=None,
                        help="Espacio de nombres de red para nftables (ej. ns-gateway o gateway)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Ejecuta en modo simulación sin modificar nftables real")
    parser.add_argument("--threshold", "-t", type=float, default=0.85,
                        help="Umbral mínimo de puntuación de IA (default: 0.85)")
    parser.add_argument("--run-id", "-r", default=None,
                        help="Identificador de la corrida (autogenerado por defecto)")
    parser.add_argument("--timeout", type=int, default=0,
                        help="Duración máxima de captura en segundos (0 para indefinido)")
    parser.add_argument("--audit-log", default=str(PROJECT_ROOT / "logs" / "audit.jsonl"),
                        help="Ruta del archivo de registro estructurado JSONL")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    pipeline = LiveInferencePipeline(
        audit_log_path=args.audit_log,
        netns=args.netns,
        dry_run=args.dry_run,
        min_score=args.threshold,
        run_id=args.run_id
    )

    if args.pcap:
        pipeline.process_pcap(args.pcap)
    else:
        pipeline.start_sniffing(
            interface=args.interface,
            timeout=args.timeout
        )


if __name__ == "__main__":
    main()
