#!/usr/bin/env python3
"""
FireNet-AI - Motor de Políticas (Fase 3)
Evalúa scores de ML, aplica allowlist, persistencia, cooldown y rate limit.
"""

import time
from enum import Enum
from dataclasses import dataclass
from typing import Tuple, Optional, Set, Dict, Any, Union
from src.models import DynamicRule


class ActionState(Enum):
    OBSERVE = "OBSERVE"
    ALERT = "ALERT"
    PROPOSE = "PROPOSE"
    APPLY = "APPLY"
    EXPIRE = "EXPIRE"
    REVOKE = "REVOKE"


# Alias de compatibilidad para pipeline.py
PolicyAction = ActionState


@dataclass
class PolicyDecision:
    action: ActionState
    reason: str
    rule: Optional[DynamicRule] = None


class PolicyEngine:
    def __init__(
        self,
        min_score: float = 0.85,
        protected_ips: Optional[Set[{
    "10.0.1.1", "10.0.2.1", "10.0.3.1",  # Interfaces del Gateway
    "10.0.2.10",                         # Servidor Target IPv4
    "fd00:1::1", "fd00:2::1", "fd00:3::1", # Gateways IPv6
    "fd00:2::10",                        # Servidor Target IPv6
    "192.168.10.1", "192.168.20.1"       # Compatibilidad tests unitarios
}]] = None,
        protected_ports: Optional[Set[int]] = None,
        max_rules_per_min: int = 10,
        cooldown_seconds: int = 5,
        config: Optional[Dict[str, Any]] = None
    ):
        if config:
            self.min_score = config.get("min_score", min_score)
            self.protected_ips = set(config.get("protected_ips", protected_ips or {"192.168.10.1", "192.168.20.1", "fd00:10::1", "fd00:20::1"}))
            self.protected_ports = set(config.get("protected_ports", protected_ports or {22, 80}))
            self.max_rules_per_min = config.get("max_rules_per_min", max_rules_per_min)
            self.cooldown_seconds = config.get("cooldown_seconds", cooldown_seconds)
        else:
            self.min_score = min_score
            self.protected_ips = protected_ips or {"192.168.10.1", "192.168.20.1", "fd00:10::1", "fd00:20::1"}
            self.protected_ports = protected_ports or {22, 80}
            self.max_rules_per_min = max_rules_per_min
            self.cooldown_seconds = cooldown_seconds

        # Historial de observaciones por IP de origen
        self.ip_history = {}  # {src_ip: [timestamps]}
        self.last_rule_time = {}  # {src_ip: last_apply_timestamp}
        self.rules_created_window = []
        self.active_rules = {}

    def _is_protected(self, src_ip: str, dst_ip: str, dst_port: Optional[int]) -> bool:
        if src_ip in self.protected_ips or dst_ip in self.protected_ips:
            return True
        if dst_port and dst_port in self.protected_ports:
            return True
        return False

    def record_applied(self, rule: DynamicRule, timestamp: Optional[float] = None):
        self.active_rules[rule.rule_id] = rule

    def record_expired(self, rule_id: str):
        self.active_rules.pop(rule_id, None)

    def record_revoked(self, rule_id: str):
        self.active_rules.pop(rule_id, None)

    def evaluate(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        score: float = 0.0,
        proto: str = "TCP",
        dst_port: Optional[int] = None,
        is_volumetric: bool = False,
        flow_key: Optional[Tuple] = None,
        flow_data: Optional[Dict[str, Any]] = None,
        current_time: Optional[float] = None
    ) -> Union[Tuple[ActionState, Optional[DynamicRule]], PolicyDecision]:
        
        # Desestructurar si se llama mediante flow_key desde pipeline.py
        if flow_key:
            src_ip = flow_key[0]
            dst_ip = flow_key[1]
            src_port = flow_key[2] if len(flow_key) > 2 else 0
            dst_port = flow_key[3] if len(flow_key) > 3 else dst_port
            proto_val = flow_key[4] if len(flow_key) > 4 else proto
            proto = "UDP" if proto_val in (17, "UDP") else "TCP"

        # 1. Umbral mínimo
        if score < self.min_score:
            res = (ActionState.OBSERVE, None)
            return PolicyDecision(action=ActionState.OBSERVE, reason="Score below threshold", rule=None) if flow_key else res

        # 2. Allowlist / IPs y Puertos protegidos
        if self._is_protected(src_ip, dst_ip, dst_port):
            res = (ActionState.ALERT, None)
            return PolicyDecision(action=ActionState.ALERT, reason="Protected entity in allowlist", rule=None) if flow_key else res

        now = current_time or time.time()

        # 3. Cooldown por IP de origen
        if src_ip in self.last_rule_time:
            if now - self.last_rule_time[src_ip] < self.cooldown_seconds:
                res = (ActionState.ALERT, None)
                return PolicyDecision(action=ActionState.ALERT, reason="Cooldown active for IP", rule=None) if flow_key else res

        # 4. Verificación de Persistencia
        if src_ip not in self.ip_history:
            self.ip_history[src_ip] = []
        self.ip_history[src_ip].append(now)

        self.ip_history[src_ip] = [t for t in self.ip_history[src_ip] if now - t <= 10]
        obs_count = len(self.ip_history[src_ip])

        required_obs = 1 if is_volumetric else 2
        if obs_count < required_obs:
            res = (ActionState.ALERT, None)
            return PolicyDecision(action=ActionState.ALERT, reason=f"Persistence threshold not met ({obs_count}/{required_obs})", rule=None) if flow_key else res

        # 5. Rate Limit global de reglas creadas
        self.rules_created_window = [t for t in self.rules_created_window if now - t <= 60]
        if len(self.rules_created_window) >= self.max_rules_per_min:
            res = (ActionState.PROPOSE, None)
            return PolicyDecision(action=ActionState.PROPOSE, reason="Global rate limit reached", rule=None) if flow_key else res

        # 6. Construir Regla Dinámica
        ttl = 120 if is_volumetric else 60
        clean_ip = str(src_ip).replace('.', '_').replace(':', '_')
        rule_id = f"rule_{int(now)}_{clean_ip}"
        
        rule = DynamicRule(
            rule_id=rule_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=proto.lower(),
            dst_port=dst_port,
            ttl=ttl,
            reason=f"Score={score:.2f}|Obs={obs_count}"
        )

        self.last_rule_time[src_ip] = now
        self.rules_created_window.append(now)

        if flow_key:
            return PolicyDecision(action=ActionState.APPLY, reason="Rule generated successfully", rule=rule)
        return ActionState.APPLY, rule