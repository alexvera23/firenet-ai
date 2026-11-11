"""
FireNet-AI - Motor de Políticas de Seguridad (Policy Engine)
Conforme a Fase 3 (Días 5-7 del ROADMAP y PROMPT1):
  - Máquina de estados finita: OBSERVE, ALERT, PROPOSE, APPLY, EXPIRE, REVOKE.
  - Verificación de umbral de puntuación mínima (T = 0.85 por defecto).
  - Aplicación de lista blanca (allowlist): IPs nunca bloqueables y puertos protegidos (22/80).
  - Verificación de persistencia: >= 2 alertas consecutivas para ataques de bajo volumen,
    1 alerta para ataques volumétricos (DDoS).
  - Rate limiting para creación de reglas dinámicas (máximo 10 reglas por minuto).
  - Período de enfriamiento (cooldown) por IP origen para mitigar rule flapping.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Set, Dict, List, Any, Tuple
import time
import uuid
import ipaddress
import logging

logger = logging.getLogger(__name__)


class PolicyAction(str, Enum):
    OBSERVE = "OBSERVE"
    ALERT = "ALERT"
    PROPOSE = "PROPOSE"
    APPLY = "APPLY"
    EXPIRE = "EXPIRE"
    REVOKE = "REVOKE"


@dataclass
class DynamicRule:
    rule_id: str
    src_ip: str
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: str = "tcp"
    ip_version: int = 4
    action: str = "drop"
    ttl: int = 60
    score: float = 0.0
    reason: str = ""
    created_at: float = field(default_factory=time.time)
    flow_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "ip_version": self.ip_version,
            "action": self.action,
            "ttl": self.ttl,
            "score": self.score,
            "reason": self.reason,
            "created_at": self.created_at,
            "flow_id": self.flow_id,
        }


@dataclass
class PolicyDecision:
    action: PolicyAction
    reason: str
    rule: Optional[DynamicRule] = None
    score: float = 0.0
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    consecutive_alerts: int = 0
    is_volumetric: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "reason": self.reason,
            "rule": self.rule.to_dict() if self.rule else None,
            "score": self.score,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "consecutive_alerts": self.consecutive_alerts,
            "is_volumetric": self.is_volumetric,
        }


# IPs estrictamente protegidas según PROMPT1
DEFAULT_PROTECTED_IPS = {
    "192.168.10.1",
    "192.168.20.1",
    "fd00:10::1",
    "fd00:20::1",
}

# Puertos protegidos según PROMPT1 (si están marcados como tales)
DEFAULT_PROTECTED_PORTS = {22, 80}


class PolicyEngine:
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        min_score: float = 0.85,
        ttl_seconds: int = 60,
        protected_ips: Optional[Set[str]] = None,
        protected_ports: Optional[Set[int]] = None,
        protect_ports: bool = True,
        max_rules_per_minute: int = 10,
        cooldown_seconds: float = 60.0,
        volumetric_pps_threshold: float = 50.0,
        volumetric_bps_threshold: float = 100_000.0,
        volumetric_packets_threshold: int = 50,
        persistence_threshold_low_volume: int = 2,
    ):
        cfg = config or {}

        self.min_score = float(cfg.get("min_score", min_score))
        self.ttl_default = int(cfg.get("ttl_seconds", ttl_seconds))

        # Configuración de Allowlist de IPs
        raw_ips = cfg.get("protected_ips", protected_ips)
        if raw_ips is None:
            self.protected_ips = set(DEFAULT_PROTECTED_IPS)
        else:
            self.protected_ips = set(raw_ips)

        # Configuración de puertos protegidos (22, 80)
        raw_ports = cfg.get("protected_ports", protected_ports)
        if raw_ports is None:
            self.protected_ports = set(DEFAULT_PROTECTED_PORTS)
        else:
            self.protected_ports = {int(p) for p in raw_ports}

        self.protect_ports = bool(cfg.get("protect_ports", protect_ports))

        # Umbrales volumétricos y de persistencia
        self.volumetric_pps_threshold = float(cfg.get("volumetric_pps_threshold", volumetric_pps_threshold))
        self.volumetric_bps_threshold = float(cfg.get("volumetric_bps_threshold", volumetric_bps_threshold))
        self.volumetric_packets_threshold = int(cfg.get("volumetric_packets_threshold", volumetric_packets_threshold))
        self.persistence_threshold_low_volume = int(cfg.get("persistence_threshold_low_volume", persistence_threshold_low_volume))

        # Rate limiting
        self.max_rules_per_minute = int(cfg.get("max_rules_per_minute", max_rules_per_minute))
        self.applied_rule_timestamps: List[float] = []

        # Cooldown y anti-flapping por IP origen
        self.cooldown_seconds = float(cfg.get("cooldown_seconds", cooldown_seconds))
        self.last_rule_time_by_ip: Dict[str, float] = {}

        # Seguimiento de estado de IPs y reglas activas
        self.consecutive_alerts_by_ip: Dict[str, int] = {}
        self.active_rules_by_ip: Dict[str, DynamicRule] = {}
        self.rules_by_id: Dict[str, DynamicRule] = {}
        self.ip_states: Dict[str, PolicyAction] = {}

    def _normalize_ip(self, ip_str: Optional[str]) -> Optional[str]:
        """Normaliza una dirección IPv4 o IPv6 para comparación inequívoca."""
        if not ip_str:
            return None
        try:
            return str(ipaddress.ip_address(ip_str.strip()))
        except ValueError:
            return ip_str.strip()

    def is_ip_protected(self, ip_str: Optional[str]) -> bool:
        """Verifica si la IP está en la lista blanca de entidades protegidas."""
        if not ip_str:
            return False
        norm = self._normalize_ip(ip_str)
        for prot in self.protected_ips:
            if self._normalize_ip(prot) == norm:
                return True
        return False

    def is_port_protected(self, port: Optional[int]) -> bool:
        """Verifica si el puerto destino corresponde a un servicio protegido."""
        if not self.protect_ports or port is None:
            return False
        return int(port) in self.protected_ports

    def _is_volumetric_flow(self, flow_data: Dict[str, Any]) -> bool:
        """Determina si el flujo muestra características de ataque volumétrico (DDoS)."""
        if flow_data.get("is_volumetric"):
            return True
        pps = float(flow_data.get("pps", 0.0))
        bps = float(flow_data.get("bps", 0.0))
        packets = int(flow_data.get("packets", 0))

        return (
            pps >= self.volumetric_pps_threshold
            or bps >= self.volumetric_bps_threshold
            or packets >= self.volumetric_packets_threshold
        )

    def _check_rate_limit(self, now: float) -> bool:
        """
        Verifica el límite de reglas dinámicas aplicadas en el último minuto.
        Retorna True si la tasa está dentro del límite permitido, False si excedió.
        """
        one_minute_ago = now - 60.0
        # Filtrar timestamps anteriores a 60 segundos
        self.applied_rule_timestamps = [
            t for t in self.applied_rule_timestamps if t > one_minute_ago
        ]
        return len(self.applied_rule_timestamps) < self.max_rules_per_minute

    def _is_ip_in_cooldown(self, src_ip: str, now: float) -> Tuple[bool, float]:
        """
        Verifica si la IP de origen se encuentra en período de espera (cooldown)
        para evitar inestabilidad (flapping).
        """
        last_time = self.last_rule_time_by_ip.get(src_ip)
        if last_time is None:
            return False, 0.0

        elapsed = now - last_time
        if elapsed < self.cooldown_seconds:
            remaining = self.cooldown_seconds - elapsed
            return True, remaining
        return False, 0.0

    def evaluate(
        self,
        flow_key: Any,
        score: float,
        flow_data: Dict[str, Any],
        current_time: Optional[float] = None
    ) -> PolicyDecision:
        """
        Evalúa un flujo y su puntuación de IA contra las políticas de seguridad.

        flow_key: tupla (src_ip, dst_ip, src_port, dst_port, protocol) o string identificador
        score: probabilidad calculada por el modelo ML [0.0, 1.0]
        flow_data: diccionario con características del flujo (dst_port, protocol, ip_version, pps, bps, etc.)
        """
        now = current_time or time.time()

        # Extraer parámetros de flujo
        if isinstance(flow_key, (list, tuple)) and len(flow_key) >= 2:
            src_ip = str(flow_key[0])
            dst_ip = str(flow_key[1])
            src_port = int(flow_key[2]) if len(flow_key) > 2 else flow_data.get("src_port", 0)
            dst_port = int(flow_key[3]) if len(flow_key) > 3 else flow_data.get("dst_port", 0)
            proto_val = flow_key[4] if len(flow_key) > 4 else flow_data.get("protocol", 6)
        else:
            src_ip = str(flow_data.get("initiator_ip") or flow_data.get("src_ip", "0.0.0.0"))
            dst_ip = str(flow_data.get("responder_ip") or flow_data.get("dst_ip", "0.0.0.0"))
            src_port = int(flow_data.get("src_port", 0))
            dst_port = int(flow_data.get("dst_port", 0))
            proto_val = flow_data.get("protocol", 6)

        norm_src = self._normalize_ip(src_ip)
        norm_dst = self._normalize_ip(dst_ip)
        dst_port = int(flow_data.get("dst_port", dst_port or 0))

        # 1. Verificación de Lista Blanca (Allowlist de IPs y Puertos Protegidos)
        if self.is_ip_protected(src_ip) or self.is_ip_protected(dst_ip):
            self.ip_states[src_ip] = PolicyAction.ALERT
            return PolicyDecision(
                action=PolicyAction.ALERT,
                reason="Allowlisted IP involved; blocking prohibited",
                score=score,
                src_ip=src_ip,
                dst_ip=dst_ip,
                consecutive_alerts=self.consecutive_alerts_by_ip.get(src_ip, 0),
            )

        if self.is_port_protected(dst_port):
            self.ip_states[src_ip] = PolicyAction.ALERT
            return PolicyDecision(
                action=PolicyAction.ALERT,
                reason=f"Allowlisted port {dst_port} protected; blocking prohibited",
                score=score,
                src_ip=src_ip,
                dst_ip=dst_ip,
                consecutive_alerts=self.consecutive_alerts_by_ip.get(src_ip, 0),
            )

        # 2. Verificación de Umbral de Puntuación (Score Threshold)
        if score < self.min_score:
            # Tráfico benigno o sospecha insuficiente: reset de alertas consecutivas
            self.consecutive_alerts_by_ip[src_ip] = 0
            self.ip_states[src_ip] = PolicyAction.OBSERVE
            return PolicyDecision(
                action=PolicyAction.OBSERVE,
                reason=f"Score ({score:.4f}) below threshold ({self.min_score:.2f})",
                score=score,
                src_ip=src_ip,
                dst_ip=dst_ip,
                consecutive_alerts=0,
            )

        # 3. Clasificación Volumétrica y Verificación de Persistencia
        is_volumetric = self._is_volumetric_flow(flow_data)
        required_alerts = 1 if is_volumetric else self.persistence_threshold_low_volume

        current_alerts = self.consecutive_alerts_by_ip.get(src_ip, 0) + 1
        self.consecutive_alerts_by_ip[src_ip] = current_alerts

        # Si aún no alcanza el umbral de persistencia requerido
        if current_alerts < required_alerts:
            self.ip_states[src_ip] = PolicyAction.ALERT
            return PolicyDecision(
                action=PolicyAction.ALERT,
                reason=(
                    f"Awaiting persistence validation ({current_alerts}/{required_alerts}) "
                    f"for low-volume threat"
                ),
                score=score,
                src_ip=src_ip,
                dst_ip=dst_ip,
                consecutive_alerts=current_alerts,
                is_volumetric=is_volumetric,
            )

        # 4. Transición a PROPOSE: Preparar regla candidata
        self.ip_states[src_ip] = PolicyAction.PROPOSE

        # 5. Verificación de Regla Activa Existente (Anti-Duplicidad)
        if src_ip in self.active_rules_by_ip:
            active = self.active_rules_by_ip[src_ip]
            return PolicyDecision(
                action=PolicyAction.OBSERVE,
                reason=f"Active drop rule already enforced for {src_ip} (Rule ID: {active.rule_id})",
                rule=active,
                score=score,
                src_ip=src_ip,
                dst_ip=dst_ip,
                consecutive_alerts=current_alerts,
                is_volumetric=is_volumetric,
            )

        # 6. Verificación de Período de Enfriamiento (Cooldown / Anti-Flapping)
        in_cooldown, remaining = self._is_ip_in_cooldown(src_ip, now)
        if in_cooldown:
            self.ip_states[src_ip] = PolicyAction.ALERT
            return PolicyDecision(
                action=PolicyAction.ALERT,
                reason=f"Cooldown active for source IP {src_ip} ({remaining:.1f}s remaining, anti-flapping)",
                score=score,
                src_ip=src_ip,
                dst_ip=dst_ip,
                consecutive_alerts=current_alerts,
                is_volumetric=is_volumetric,
            )

        # 7. Verificación de Rate Limiting (Máx 10 reglas por minuto)
        if not self._check_rate_limit(now):
            self.ip_states[src_ip] = PolicyAction.ALERT
            return PolicyDecision(
                action=PolicyAction.ALERT,
                reason=f"Rate limit exceeded: maximum {self.max_rules_per_minute} rules/min reached",
                score=score,
                src_ip=src_ip,
                dst_ip=dst_ip,
                consecutive_alerts=current_alerts,
                is_volumetric=is_volumetric,
            )

        # 8. Transición a APPLY: Sintetizar regla dinámica
        ip_ver = int(flow_data.get("ip_version", 4))
        # Determinar protocolo
        proto_str = "tcp"
        if isinstance(proto_val, str):
            proto_str = proto_val.lower()
        elif proto_val == 17:
            proto_str = "udp"
        elif proto_val in (1, 58):
            proto_str = "icmp"

        rule_id = f"firenet_{uuid.uuid4().hex[:8]}"
        threat_type = "Volumetric DDoS" if is_volumetric else f"Low-Volume ({current_alerts} alerts)"
        reason = f"AI Detection: {threat_type} (Score: {score:.4f})"

        candidate_rule = DynamicRule(
            rule_id=rule_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port if dst_port > 0 else None,
            protocol=proto_str,
            ip_version=ip_ver,
            action="drop",
            ttl=self.ttl_default,
            score=score,
            reason=reason,
            created_at=now,
            flow_id=str(flow_key) if not isinstance(flow_key, (list, tuple)) else None,
        )

        self.ip_states[src_ip] = PolicyAction.APPLY

        return PolicyDecision(
            action=PolicyAction.APPLY,
            reason=reason,
            rule=candidate_rule,
            score=score,
            src_ip=src_ip,
            dst_ip=dst_ip,
            consecutive_alerts=current_alerts,
            is_volumetric=is_volumetric,
        )

    def record_applied(self, rule: DynamicRule, timestamp: Optional[float] = None) -> None:
        """Registra la aplicación efectiva de una regla dinámica en el firewall."""
        now = timestamp or time.time()
        self.applied_rule_timestamps.append(now)
        self.active_rules_by_ip[rule.src_ip] = rule
        self.rules_by_id[rule.rule_id] = rule
        self.last_rule_time_by_ip[rule.src_ip] = now
        self.ip_states[rule.src_ip] = PolicyAction.APPLY
        logger.info(f"[POLICY] Regla {rule.rule_id} aplicada para IP {rule.src_ip} (TTL={rule.ttl}s)")

    def record_expired(self, rule_id: str, timestamp: Optional[float] = None) -> Optional[DynamicRule]:
        """Registra la expiración de una regla por TTL (estado EXPIRE)."""
        now = timestamp or time.time()
        rule = self.rules_by_id.pop(rule_id, None)
        if rule:
            if self.active_rules_by_ip.get(rule.src_ip) == rule:
                del self.active_rules_by_ip[rule.src_ip]
            self.last_rule_time_by_ip[rule.src_ip] = now
            self.ip_states[rule.src_ip] = PolicyAction.EXPIRE
            logger.info(f"[POLICY] Regla {rule_id} expirada por TTL para IP {rule.src_ip}")
        return rule

    def record_revoked(self, rule_id: str, timestamp: Optional[float] = None) -> Optional[DynamicRule]:
        """Registra la revocación manual o rollback de una regla (estado REVOKE)."""
        now = timestamp or time.time()
        rule = self.rules_by_id.pop(rule_id, None)
        if rule:
            if self.active_rules_by_ip.get(rule.src_ip) == rule:
                del self.active_rules_by_ip[rule.src_ip]
            self.last_rule_time_by_ip[rule.src_ip] = now
            self.ip_states[rule.src_ip] = PolicyAction.REVOKE
            logger.info(f"[POLICY] Regla {rule_id} revocada para IP {rule.src_ip}")
        return rule

    def get_ip_state(self, ip_str: str) -> PolicyAction:
        """Retorna el estado actual de la máquina de estados para una IP específica."""
        return self.ip_states.get(ip_str, PolicyAction.OBSERVE)

    def reset(self) -> None:
        """Restablece el estado completo del motor de políticas."""
        self.applied_rule_timestamps.clear()
        self.last_rule_time_by_ip.clear()
        self.consecutive_alerts_by_ip.clear()
        self.active_rules_by_ip.clear()
        self.rules_by_id.clear()
        self.ip_states.clear()
