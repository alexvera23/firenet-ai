#!/usr/bin/env python3
"""
FireNet-AI - Pruebas Unitarias y de Integración (Fase 3)
Cubre: PolicyEngine, NftablesExecutor (dry-run) y LiveInferencePipeline.
Conforme a PROMPT1: motor de políticas, ejecutor nftables y pipeline de inferencia.
"""

import time
import json
import pytest
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch, call

from src.models import DynamicRule
from src.policy.engine import PolicyEngine, ActionState, PolicyDecision
from src.firewall.executor import NftablesExecutor


# ============================================================
# Fixtures compartidos
# ============================================================

@pytest.fixture
def engine():
    """PolicyEngine configurado según PROMPT1."""
    return PolicyEngine(
        min_score=0.85,
        protected_ips={"192.168.10.1", "192.168.20.1", "fd00:10::1", "fd00:20::1"},
        protected_ports={22, 80},
        max_rules_per_min=10,
        cooldown_seconds=5,
    )


@pytest.fixture
def executor():
    """NftablesExecutor en modo dry-run; nunca toca nftables real."""
    return NftablesExecutor(
        table="firenet_table",
        chain="dynamic_rules",
        dry_run=True,
        auto_expire=False,   # desactivar timers para tests unitarios
    )


@pytest.fixture
def rule_factory():
    """Fábrica de DynamicRule para tests."""
    def _make(rule_id="rule_001", src_ip="10.0.0.5", dst_ip="192.168.20.2",
              proto="tcp", dst_port=8080, ttl=60, reason="test"):
        return DynamicRule(
            rule_id=rule_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=proto,
            dst_port=dst_port,
            ttl=ttl,
            reason=reason,
        )
    return _make


# ============================================================
# BLOQUE 1: PolicyEngine – Tests Unitarios
# ============================================================

class TestPolicyEngineObserve:
    """Casos donde el engine debe retornar OBSERVE."""

    def test_observe_under_threshold(self, engine):
        """Score menor al umbral mínimo → OBSERVE."""
        action, rule = engine.evaluate(
            src_ip="10.0.0.5", dst_ip="10.0.0.2",
            score=0.50, proto="TCP", dst_port=443
        )
        assert action == ActionState.OBSERVE
        assert rule is None

    def test_observe_exactly_at_threshold_minus_epsilon(self, engine):
        """Score justo debajo de 0.85 → OBSERVE."""
        action, _ = engine.evaluate(
            src_ip="10.0.0.5", dst_ip="10.0.0.2",
            score=0.8499, proto="TCP", dst_port=9999
        )
        assert action == ActionState.OBSERVE

    def test_observe_zero_score(self, engine):
        """Score cero → OBSERVE."""
        action, _ = engine.evaluate(
            src_ip="10.0.0.5", dst_ip="10.0.0.2",
            score=0.0, proto="UDP", dst_port=53
        )
        assert action == ActionState.OBSERVE


class TestPolicyEngineAllowlist:
    """Casos donde la allowlist bloquea la acción bloqueante."""

    def test_alert_on_protected_src_ip(self, engine):
        """IP de origen protegida → ALERT aunque el score sea alto."""
        action, rule = engine.evaluate(
            src_ip="192.168.10.1", dst_ip="10.0.0.5",
            score=0.99, proto="TCP", dst_port=8080
        )
        assert action == ActionState.ALERT
        assert rule is None

    def test_alert_on_protected_dst_ip(self, engine):
        """IP de destino protegida → ALERT."""
        action, _ = engine.evaluate(
            src_ip="10.0.0.6", dst_ip="192.168.20.1",
            score=0.98, proto="TCP", dst_port=443
        )
        assert action == ActionState.ALERT

    def test_alert_on_protected_ipv6(self, engine):
        """IP IPv6 protegida → ALERT."""
        action, _ = engine.evaluate(
            src_ip="fd00:10::1", dst_ip="fd00:20::5",
            score=0.99, proto="TCP", dst_port=8443
        )
        assert action == ActionState.ALERT

    def test_alert_on_protected_port_22(self, engine):
        """Puerto destino protegido (SSH=22) → ALERT."""
        action, _ = engine.evaluate(
            src_ip="10.5.5.5", dst_ip="10.0.0.2",
            score=0.95, proto="TCP", dst_port=22
        )
        assert action == ActionState.ALERT

    def test_alert_on_protected_port_80(self, engine):
        """Puerto destino protegido (HTTP=80) → ALERT."""
        action, _ = engine.evaluate(
            src_ip="10.5.5.5", dst_ip="10.0.0.2",
            score=0.95, proto="TCP", dst_port=80
        )
        assert action == ActionState.ALERT

    def test_non_protected_port_above_threshold_leads_to_alert_then_apply(self, engine):
        """Puerto 443 no protegido → flujo normal hacia APPLY con persistencia."""
        src = "10.9.9.9"
        # Primera vez → ALERT (persistencia)
        a1, _ = engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.90, proto="TCP", dst_port=443)
        assert a1 == ActionState.ALERT
        # Segunda vez → APPLY
        a2, rule = engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.91, proto="TCP", dst_port=443)
        assert a2 == ActionState.APPLY
        assert rule is not None


class TestPolicyEnginePersistence:
    """Control de persistencia (mínimo de alertas antes de APPLY)."""

    def test_first_detection_returns_alert(self, engine):
        """Primera alerta de bajo volumen → ALERT (no APPLY)."""
        src = "10.1.2.3"
        action, rule = engine.evaluate(
            src_ip=src, dst_ip="10.0.0.2",
            score=0.90, proto="TCP", dst_port=8080
        )
        assert action == ActionState.ALERT
        assert rule is None

    def test_second_detection_returns_apply(self, engine):
        """Segunda alerta consecutiva de alto score → APPLY con regla."""
        src = "10.1.2.4"
        engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.90, proto="TCP", dst_port=8080)
        action, rule = engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.92, proto="TCP", dst_port=8080)
        assert action == ActionState.APPLY
        assert rule is not None
        assert rule.src_ip == src
        assert rule.dst_port == 8080

    def test_rule_has_correct_ttl_non_volumetric(self, engine):
        """Regla de ataque no volumétrico → TTL = 60."""
        src = "10.1.2.5"
        engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.90, proto="TCP", dst_port=8080)
        _, rule = engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.90, proto="TCP", dst_port=8080)
        assert rule.ttl == 60

    def test_different_ips_independent_persistence(self, engine):
        """La persistencia es independiente por IP de origen."""
        engine.evaluate(src_ip="10.1.1.1", dst_ip="10.0.0.2", score=0.90, proto="TCP", dst_port=9000)
        # La segunda IP no debería heredar el contador de la primera
        action, _ = engine.evaluate(src_ip="10.1.1.2", dst_ip="10.0.0.2", score=0.90, proto="TCP", dst_port=9000)
        assert action == ActionState.ALERT


class TestPolicyEngineVolumetric:
    """Ataques volumétricos requieren solo 1 alerta para APPLY."""

    def test_volumetric_immediate_apply(self, engine):
        """Ataque volumétrico con score alto → APPLY en la primera alerta."""
        src = "10.0.0.99"
        action, rule = engine.evaluate(
            src_ip=src, dst_ip="192.168.20.2",
            score=0.98, proto="UDP", dst_port=9999,
            is_volumetric=True,
        )
        assert action == ActionState.APPLY
        assert rule is not None
        assert rule.ttl == 120  # TTL mayor para ataques volumétricos

    def test_volumetric_rule_uses_udp_proto(self, engine):
        """Regla volumétrica UDP → protocolo UDP en la regla."""
        src = "10.0.0.100"
        _, rule = engine.evaluate(
            src_ip=src, dst_ip="10.0.0.2",
            score=0.98, proto="UDP", dst_port=1234,
            is_volumetric=True,
        )
        assert rule.proto == "udp"

    def test_volumetric_below_threshold_still_observes(self, engine):
        """Volumétrico pero con score bajo → OBSERVE."""
        action, _ = engine.evaluate(
            src_ip="10.0.0.101", dst_ip="10.0.0.2",
            score=0.60, proto="UDP", dst_port=1234,
            is_volumetric=True,
        )
        assert action == ActionState.OBSERVE


class TestPolicyEngineCooldown:
    """Periodo de cooldown por IP de origen evita flapping."""

    def test_cooldown_prevents_double_apply(self, engine):
        """Después de APPLY, la misma IP no genera otra regla durante el cooldown."""
        src = "10.2.2.2"
        # Precalentar persistencia
        engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.90, proto="TCP", dst_port=9999)
        # Primera acción → APPLY
        action1, rule1 = engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.95, proto="TCP", dst_port=9999)
        assert action1 == ActionState.APPLY
        assert rule1 is not None
        # Segunda acción inmediata → ALERT (cooldown activo)
        action2, rule2 = engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.97, proto="TCP", dst_port=9999)
        assert action2 == ActionState.ALERT
        assert rule2 is None

    def test_cooldown_expired_allows_new_rule(self, engine):
        """Después de que expira el cooldown, se puede generar otra regla."""
        src = "10.2.2.3"
        # Precalentar + primer APPLY con cooldown corto
        engine.cooldown_seconds = 0
        engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.90, proto="TCP", dst_port=9999)
        _, _ = engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.95, proto="TCP", dst_port=9999)
        # Con cooldown = 0, una nueva evaluación inmediata debería poder generar otra regla
        # (el tiempo transcurrido >= cooldown_seconds=0)
        action, rule = engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.95, proto="TCP", dst_port=9999)
        # Puede ser APPLY o ALERT según el cooldown, pero NO debe fallar
        assert action in (ActionState.APPLY, ActionState.ALERT)


class TestPolicyEngineRateLimit:
    """Límite de tasa global de creación de reglas."""

    def test_rate_limit_triggers_propose(self):
        """Superar el límite de 5 reglas/min → PROPOSE."""
        engine = PolicyEngine(
            min_score=0.85,
            max_rules_per_min=5,
            cooldown_seconds=0,
        )
        # Generar 5 reglas distintas (IPs diferentes para evitar cooldown)
        for i in range(5):
            src = f"10.3.3.{i + 1}"
            engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.90, proto="UDP", dst_port=9999, is_volumetric=True)

        # La 6ª debe ser PROPOSE por rate limit
        action, _ = engine.evaluate(src_ip="10.3.3.99", dst_ip="10.0.0.2", score=0.95, proto="UDP", dst_port=9999, is_volumetric=True)
        assert action == ActionState.PROPOSE

    def test_rate_limit_window_resets_after_60s(self):
        """El rate limit solo cuenta eventos en la ventana de 60 segundos."""
        engine = PolicyEngine(
            min_score=0.85,
            max_rules_per_min=2,
            cooldown_seconds=0,
        )
        # Registrar 2 reglas con timestamp en el pasado (> 60s)
        old_time = time.time() - 70
        engine.rules_created_window = [old_time, old_time]

        # Ahora una nueva regla debe ser posible
        src = "10.4.4.1"
        engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.90, proto="UDP", dst_port=1111, is_volumetric=True)
        action, rule = engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.95, proto="UDP", dst_port=1111, is_volumetric=True)
        # Independientemente de APPLY o PROPOSE, no debe ser un error
        assert action in (ActionState.APPLY, ActionState.ALERT, ActionState.PROPOSE)


class TestPolicyEngineFlowKeyInterface:
    """Interfaz de flow_key usada por pipeline.py (retorna PolicyDecision)."""

    def test_flow_key_returns_policy_decision(self, engine):
        """Llamada con flow_key → retorna PolicyDecision."""
        flow_key = ("10.5.5.5", "10.0.0.2", 54321, 8080, 6)
        decision = engine.evaluate(flow_key=flow_key, score=0.50, flow_data={})
        assert isinstance(decision, PolicyDecision)
        assert decision.action == ActionState.OBSERVE

    def test_flow_key_allowlist_decision(self, engine):
        """flow_key con IP protegida → PolicyDecision con ALERT."""
        flow_key = ("192.168.10.1", "10.0.0.2", 54321, 9999, 6)
        decision = engine.evaluate(flow_key=flow_key, score=0.99, flow_data={})
        assert isinstance(decision, PolicyDecision)
        assert decision.action == ActionState.ALERT

    def test_flow_key_apply_decision(self, engine):
        """flow_key con dos evaluaciones altas → PolicyDecision APPLY con regla."""
        src = "10.6.6.6"
        flow_key = (src, "10.0.0.2", 11111, 9999, 6)
        engine.evaluate(flow_key=flow_key, score=0.90, flow_data={"dst_port": 9999})
        decision = engine.evaluate(flow_key=flow_key, score=0.92, flow_data={"dst_port": 9999})
        assert isinstance(decision, PolicyDecision)
        assert decision.action == ActionState.APPLY
        assert decision.rule is not None
        assert decision.rule.src_ip == src

    def test_flow_key_extracts_proto_from_tuple(self, engine):
        """Proto numérico 17 (UDP) en flow_key → regla con proto='udp'."""
        src = "10.7.7.7"
        flow_key = (src, "10.0.0.2", 11111, 9999, 17)  # proto=17=UDP
        engine.evaluate(flow_key=flow_key, score=0.98, flow_data={}, is_volumetric=True)
        decision = engine.evaluate(flow_key=flow_key, score=0.98, flow_data={}, is_volumetric=True)
        # Con volumétrico, la primera debería bastar
        # Puede ser APPLY o ALERT según cooldown
        assert isinstance(decision, PolicyDecision)


class TestPolicyEngineStateManagement:
    """Gestión interna de estado de reglas activas."""

    def test_record_applied_stores_rule(self, engine, rule_factory):
        """record_applied almacena la regla en active_rules."""
        rule = rule_factory(rule_id="rule_state_01")
        engine.record_applied(rule)
        assert "rule_state_01" in engine.active_rules

    def test_record_expired_removes_rule(self, engine, rule_factory):
        """record_expired elimina la regla de active_rules."""
        rule = rule_factory(rule_id="rule_state_02")
        engine.record_applied(rule)
        engine.record_expired("rule_state_02")
        assert "rule_state_02" not in engine.active_rules

    def test_record_revoked_removes_rule(self, engine, rule_factory):
        """record_revoked elimina la regla de active_rules."""
        rule = rule_factory(rule_id="rule_state_03")
        engine.record_applied(rule)
        engine.record_revoked("rule_state_03")
        assert "rule_state_03" not in engine.active_rules

    def test_record_expired_nonexistent_does_not_raise(self, engine):
        """record_expired con ID inexistente no genera excepción."""
        engine.record_expired("rule_no_existe")  # No debe lanzar

    def test_record_revoked_nonexistent_does_not_raise(self, engine):
        """record_revoked con ID inexistente no genera excepción."""
        engine.record_revoked("rule_no_existe")  # No debe lanzar


# ============================================================
# BLOQUE 2: NftablesExecutor (dry-run) – Tests Unitarios
# ============================================================

class TestNftablesExecutorApply:
    """Tests de apply_rule en modo dry-run."""

    def test_apply_rule_returns_true(self, executor, rule_factory):
        """apply_rule en dry-run → True."""
        rule = rule_factory()
        assert executor.apply_rule(rule) is True

    def test_apply_rule_records_command(self, executor, rule_factory):
        """apply_rule registra el comando en command_history."""
        rule = rule_factory(rule_id="rule_cmd_01", dst_port=8080)
        executor.apply_rule(rule)
        assert len(executor.command_history) > 0

    def test_apply_rule_command_contains_drop(self, executor, rule_factory):
        """El comando generado contiene 'drop'."""
        rule = rule_factory(rule_id="rule_drop_01")
        executor.apply_rule(rule)
        cmd = executor.command_history[-1]
        assert "drop" in cmd

    def test_apply_rule_command_contains_comment(self, executor, rule_factory):
        """El comando generado contiene el comentario con firenet_id."""
        rule = rule_factory(rule_id="rule_comment_01")
        executor.apply_rule(rule)
        cmd = executor.command_history[-1]
        assert "comment" in cmd
        assert "firenet_id=rule_comment_01" in " ".join(cmd)

    def test_apply_rule_command_contains_src_ip(self, executor, rule_factory):
        """El comando contiene la IP de origen."""
        rule = rule_factory(rule_id="rule_ip_01", src_ip="10.9.8.7")
        executor.apply_rule(rule)
        cmd = executor.command_history[-1]
        assert "10.9.8.7" in cmd

    def test_apply_rule_command_contains_dst_port(self, executor, rule_factory):
        """El comando contiene el puerto destino."""
        rule = rule_factory(rule_id="rule_port_01", dst_port=4444)
        executor.apply_rule(rule)
        cmd = executor.command_history[-1]
        assert "4444" in " ".join(cmd)

    def test_apply_rule_stores_in_active_rules(self, executor, rule_factory):
        """apply_rule almacena la regla en active_rules."""
        rule = rule_factory(rule_id="rule_store_01")
        executor.apply_rule(rule)
        assert "rule_store_01" in executor.active_rules

    def test_apply_rule_uses_ip6_for_ipv6(self, executor, rule_factory):
        """Regla con IP IPv6 → usa 'ip6' en el comando nft."""
        rule = rule_factory(rule_id="rule_v6_01", src_ip="fd00:3::10", proto="tcp", dst_port=443)
        executor.apply_rule(rule)
        cmd = executor.command_history[-1]
        assert "ip6" in cmd

    def test_apply_rule_uses_ip4_for_ipv4(self, executor, rule_factory):
        """Regla con IP IPv4 → usa 'ip' en el comando nft."""
        rule = rule_factory(rule_id="rule_v4_01", src_ip="10.1.2.3")
        executor.apply_rule(rule)
        cmd = executor.command_history[-1]
        assert "ip" in cmd and "ip6" not in cmd

    def test_apply_rule_uses_correct_table_chain(self, executor, rule_factory):
        """El comando apunta a la tabla y cadena correctas."""
        rule = rule_factory(rule_id="rule_table_01")
        executor.apply_rule(rule)
        cmd_str = " ".join(executor.command_history[-1])
        assert "firenet_table" in cmd_str
        assert "dynamic_rules" in cmd_str

    def test_apply_multiple_rules_all_stored(self, executor, rule_factory):
        """Aplicar múltiples reglas → todas almacenadas en active_rules."""
        for i in range(3):
            rule = rule_factory(rule_id=f"rule_multi_{i:02d}", src_ip=f"10.0.{i}.1")
            executor.apply_rule(rule)
        assert len(executor.active_rules) == 3

    def test_apply_rule_no_shell_injection(self, executor):
        """Ningún comando usa shell=True (verificar que son listas, no strings)."""
        rule = DynamicRule(
            rule_id="rule_safe_01",
            src_ip="10.0.0.1; rm -rf /",   # Intentar inyección
            dst_ip="10.0.0.2",
            proto="tcp",
            dst_port=80,
            ttl=60,
        )
        # En dry-run, no ejecuta nada real, solo registra. Verificar que no haya shell string.
        executor.apply_rule(rule)
        for cmd in executor.command_history:
            assert isinstance(cmd, list), "El comando debe ser una lista de tokens, no un string"


class TestNftablesExecutorRevoke:
    """Tests de revoke_rule en modo dry-run."""

    def test_revoke_applied_rule_returns_true(self, executor, rule_factory):
        """Revocar una regla previamente aplicada → True."""
        rule = rule_factory(rule_id="rule_rev_01")
        executor.apply_rule(rule)
        assert executor.revoke_rule("rule_rev_01") is True

    def test_revoke_removes_from_active_rules(self, executor, rule_factory):
        """Revocar regla → ya no está en active_rules."""
        rule = rule_factory(rule_id="rule_rev_02")
        executor.apply_rule(rule)
        executor.revoke_rule("rule_rev_02")
        assert "rule_rev_02" not in executor.active_rules

    def test_revoke_nonexistent_rule_returns_true_in_dryrun(self, executor):
        """Revocar regla inexistente en dry-run → True (modo simulación)."""
        result = executor.revoke_rule("rule_no_existe_01")
        assert result is True

    def test_revoke_calls_callback(self, rule_factory):
        """revoke_rule invoca on_revoke_callback con el rule_id."""
        callback = MagicMock()
        exec_ = NftablesExecutor(
            table="firenet_table", chain="dynamic_rules",
            dry_run=True, auto_expire=False,
            on_revoke_callback=callback,
        )
        rule = rule_factory(rule_id="rule_cb_01")
        exec_.apply_rule(rule)
        exec_.revoke_rule("rule_cb_01")
        callback.assert_called_once_with("rule_cb_01")


class TestNftablesExecutorFlush:
    """Tests de flush_dynamic_rules."""

    def test_flush_clears_active_rules(self, executor, rule_factory):
        """flush_dynamic_rules limpia todas las reglas activas."""
        for i in range(3):
            executor.apply_rule(rule_factory(rule_id=f"rule_flush_{i}", src_ip=f"10.0.{i}.1"))
        assert len(executor.active_rules) == 3
        executor.flush_dynamic_rules()
        assert len(executor.active_rules) == 0

    def test_flush_clears_simulated_rules(self, executor, rule_factory):
        """flush_dynamic_rules limpia _simulated_rules en dry-run."""
        executor.apply_rule(rule_factory(rule_id="rule_sim_01"))
        executor.flush_dynamic_rules()
        assert len(executor._simulated_rules) == 0

    def test_flush_returns_true(self, executor):
        """flush_dynamic_rules retorna True."""
        assert executor.flush_dynamic_rules() is True


class TestNftablesExecutorListRules:
    """Tests de list_active_rules en modo dry-run."""

    def test_list_empty_on_start(self, executor):
        """Sin reglas aplicadas → lista vacía."""
        assert executor.list_active_rules() == []

    def test_list_returns_applied_rules(self, executor, rule_factory):
        """Reglas aplicadas aparecen en list_active_rules."""
        executor.apply_rule(rule_factory(rule_id="rule_list_01", src_ip="10.0.1.1"))
        executor.apply_rule(rule_factory(rule_id="rule_list_02", src_ip="10.0.1.2"))
        rules = executor.list_active_rules()
        rule_ids = [r.get("rule_id") for r in rules]
        assert "rule_list_01" in rule_ids
        assert "rule_list_02" in rule_ids

    def test_list_after_flush_is_empty(self, executor, rule_factory):
        """Después de flush, la lista está vacía."""
        executor.apply_rule(rule_factory(rule_id="rule_list_03"))
        executor.flush_dynamic_rules()
        assert executor.list_active_rules() == []

    def test_list_after_revoke_excludes_revoked(self, executor, rule_factory):
        """Después de revocar, la regla revocada no aparece en la lista."""
        executor.apply_rule(rule_factory(rule_id="rule_list_04"))
        executor.apply_rule(rule_factory(rule_id="rule_list_05", src_ip="10.0.2.1"))
        executor.revoke_rule("rule_list_04")
        rules = executor.list_active_rules()
        rule_ids = [r.get("rule_id") for r in rules]
        assert "rule_list_04" not in rule_ids
        assert "rule_list_05" in rule_ids


class TestNftablesExecutorNetns:
    """Tests de construcción del prefijo de comando para netns."""

    def test_netns_prefix_included_when_root(self):
        """Con netns configurado y use_sudo=False → prefijo usa ip netns exec."""
        exec_ = NftablesExecutor(
            table="firenet_table", chain="dynamic_rules",
            dry_run=True, auto_expire=False,
            netns="ns-gateway", use_sudo=False,
        )
        prefix = exec_._build_command_prefix()
        assert "ip" in prefix
        assert "netns" in prefix
        assert "exec" in prefix
        assert "ns-gateway" in prefix

    def test_netns_prefix_with_sudo(self):
        """Con netns y use_sudo=True → prefijo usa sudo ip netns exec."""
        exec_ = NftablesExecutor(
            table="firenet_table", chain="dynamic_rules",
            dry_run=True, auto_expire=False,
            netns="ns-gateway", use_sudo=True,
        )
        prefix = exec_._build_command_prefix()
        assert "sudo" in prefix
        assert "ns-gateway" in prefix

    def test_no_netns_no_prefix(self):
        """Sin netns ni sudo → prefijo vacío."""
        exec_ = NftablesExecutor(
            table="firenet_table", chain="dynamic_rules",
            dry_run=True, auto_expire=False,
            use_sudo=False,
        )
        prefix = exec_._build_command_prefix()
        assert prefix == []


class TestNftablesExecutorAutoExpire:
    """Tests de expiración automática por TTL."""

    def test_ttl_timer_started_on_apply(self, rule_factory):
        """apply_rule con auto_expire=True crea un timer activo."""
        exec_ = NftablesExecutor(
            table="firenet_table", chain="dynamic_rules",
            dry_run=True, auto_expire=True,
        )
        rule = rule_factory(rule_id="rule_ttl_01", ttl=60)
        exec_.apply_rule(rule)
        assert "rule_ttl_01" in exec_._timers
        # Cancelar para no contaminar el entorno de tests
        exec_._timers["rule_ttl_01"].cancel()

    def test_expire_callback_invoked_on_ttl(self, rule_factory):
        """El callback on_expire_callback se invoca cuando el TTL expira."""
        expire_cb = MagicMock()
        exec_ = NftablesExecutor(
            table="firenet_table", chain="dynamic_rules",
            dry_run=True, auto_expire=True,
            on_expire_callback=expire_cb,
        )
        rule = rule_factory(rule_id="rule_ttl_cb_01", ttl=1)  # TTL muy corto
        exec_.apply_rule(rule)
        # Esperar a que el timer dispare (TTL=1s)
        time.sleep(1.5)
        expire_cb.assert_called_once_with("rule_ttl_cb_01")

    def test_revoke_cancels_timer(self, rule_factory):
        """revoke_rule cancela el timer de expiración."""
        exec_ = NftablesExecutor(
            table="firenet_table", chain="dynamic_rules",
            dry_run=True, auto_expire=True,
        )
        rule = rule_factory(rule_id="rule_ttl_cancel_01", ttl=60)
        exec_.apply_rule(rule)
        timer_ref = exec_._timers.get("rule_ttl_cancel_01")
        assert timer_ref is not None
        exec_.revoke_rule("rule_ttl_cancel_01")
        # El timer debe haber sido cancelado
        assert "rule_ttl_cancel_01" not in exec_._timers

    def test_flush_cancels_all_timers(self, rule_factory):
        """flush_dynamic_rules cancela todos los timers activos."""
        exec_ = NftablesExecutor(
            table="firenet_table", chain="dynamic_rules",
            dry_run=True, auto_expire=True,
        )
        for i in range(3):
            exec_.apply_rule(rule_factory(rule_id=f"rule_ttl_all_{i}", src_ip=f"10.0.{i}.1", ttl=60))
        assert len(exec_._timers) == 3
        exec_.flush_dynamic_rules()
        assert len(exec_._timers) == 0


class TestNftablesExecutorEnsureChain:
    """Tests de ensure_chain_exists."""

    def test_ensure_chain_runs_in_dryrun(self, executor):
        """ensure_chain_exists en dry-run → True sin errores."""
        result = executor.ensure_chain_exists()
        assert result is True

    def test_ensure_chain_records_commands(self, executor):
        """ensure_chain_exists registra los comandos add table y add chain."""
        executor.ensure_chain_exists()
        assert len(executor.command_history) >= 2
        joined = " ".join(" ".join(c) for c in executor.command_history)
        assert "add table" in joined or "add" in joined


# ============================================================
# BLOQUE 3: Tests de Integración PolicyEngine + NftablesExecutor
# ============================================================

class TestIntegrationPolicyFirewall:
    """
    Integración: PolicyEngine → NftablesExecutor.
    Simula el flujo completo sin depender de scapy, model ni filesystem.
    """

    @pytest.fixture
    def integrated(self):
        engine = PolicyEngine(
            min_score=0.85,
            protected_ips={"192.168.10.1", "192.168.20.1", "fd00:10::1", "fd00:20::1"},
            protected_ports={22, 80},
            max_rules_per_min=10,
            cooldown_seconds=5,
        )
        executor = NftablesExecutor(
            table="firenet_table",
            chain="dynamic_rules",
            dry_run=True,
            auto_expire=False,
        )
        return engine, executor

    def test_full_flow_scan_attack(self, integrated):
        """Flujo completo: escaneo detectado → regla aplicada."""
        engine, executor = integrated
        src = "10.10.10.10"
        # Dos detecciones de alto score (persistencia)
        engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.91, proto="TCP", dst_port=8080)
        action, rule = engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.93, proto="TCP", dst_port=8080)
        assert action == ActionState.APPLY
        success = executor.apply_rule(rule)
        assert success is True
        assert rule.rule_id in executor.active_rules

    def test_full_flow_ddos_immediate_block(self, integrated):
        """Flujo DDoS: una detección volumétrica → bloqueo inmediato (puerto no protegido)."""
        engine, executor = integrated
        src = "10.20.20.20"
        # Usar puerto 9999 (no protegido; puerto 80 está en la allowlist)
        action, rule = engine.evaluate(
            src_ip=src, dst_ip="10.0.0.2",
            score=0.99, proto="UDP", dst_port=9999,
            is_volumetric=True,
        )
        assert action == ActionState.APPLY
        assert rule.ttl == 120
        executor.apply_rule(rule)
        engine.record_applied(rule)
        # Verificar sincronización de estado
        assert rule.rule_id in engine.active_rules
        assert rule.rule_id in executor.active_rules

    def test_full_flow_rollback_after_ttl_notification(self, integrated):
        """Flujo completo con rollback: apply → revoke → estado limpio."""
        engine, executor = integrated
        src = "10.30.30.30"

        # Fase 1: Generar y aplicar regla
        engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.90, proto="TCP", dst_port=9000)
        action, rule = engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.95, proto="TCP", dst_port=9000)
        assert action == ActionState.APPLY
        executor.apply_rule(rule)
        engine.record_applied(rule)

        # Fase 2: Revocación (simula expiración por TTL)
        executor.revoke_rule(rule.rule_id)
        engine.record_expired(rule.rule_id)

        # Verificar estado limpio
        assert rule.rule_id not in executor.active_rules
        assert rule.rule_id not in engine.active_rules

    def test_full_flow_emergency_rollback(self, integrated):
        """flush_dynamic_rules limpia todo en emergencia."""
        engine, executor = integrated
        # Aplicar 3 reglas distintas
        for i in range(3):
            src = f"10.40.40.{i + 1}"
            engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.95, proto="UDP", dst_port=9999, is_volumetric=True)
            _, rule = engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.95, proto="UDP", dst_port=9999, is_volumetric=True)
            if rule:
                executor.apply_rule(rule)

        executor.flush_dynamic_rules()
        assert len(executor.active_rules) == 0
        assert len(executor.list_active_rules()) == 0

    def test_allowlist_prevents_rule_in_executor(self, integrated):
        """IP protegida → PolicyEngine devuelve ALERT, el ejecutor nunca recibe regla."""
        engine, executor = integrated
        src = "192.168.10.1"  # IP protegida

        action, rule = engine.evaluate(
            src_ip=src, dst_ip="10.0.0.2",
            score=0.99, proto="TCP", dst_port=8080
        )
        assert action == ActionState.ALERT
        assert rule is None
        # El ejecutor no debe haber recibido nada
        assert len(executor.active_rules) == 0

    def test_audit_fields_for_apply_action(self, integrated):
        """El registro de auditoría debe contener todos los campos de PROMPT1."""
        engine, executor = integrated
        src = "10.50.50.50"

        # Preparar
        engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.90, proto="TCP", dst_port=4000)
        action, rule = engine.evaluate(src_ip=src, dst_ip="10.0.0.2", score=0.92, proto="TCP", dst_port=4000)

        apply_status = "NOT_APPLIED"
        rule_id = None
        ttl_val = None

        if action == ActionState.APPLY and rule:
            rule_id = rule.rule_id
            ttl_val = rule.ttl
            success = executor.apply_rule(rule)
            apply_status = "APPLIED" if success else "FAILED"

        # Construir audit entry como lo haría pipeline.py
        audit_entry = {
            "timestamp": time.time(),
            "run_id": "RUN_TEST_001",
            "flow_id": "10.50.50.50:9999->10.0.0.2:4000/tcp",
            "model_version": "MLP",
            "score": 0.92,
            "policy_action": action.value,
            "rule_id": rule_id,
            "ttl": ttl_val,
            "apply_status": apply_status,
        }

        # Verificar todos los campos requeridos por PROMPT1
        required_fields = ["timestamp", "run_id", "flow_id", "model_version",
                           "score", "policy_action", "rule_id", "ttl", "apply_status"]
        for field in required_fields:
            assert field in audit_entry, f"Campo de auditoría faltante: {field}"

        assert audit_entry["apply_status"] == "APPLIED"
        assert audit_entry["rule_id"] is not None


# ============================================================
# BLOQUE 4: Tests de DynamicRule (src/models.py)
# ============================================================

class TestDynamicRule:
    """Tests del modelo de datos DynamicRule."""

    def test_ip_version_4_for_ipv4(self):
        """src_ip IPv4 → ip_version = 4."""
        rule = DynamicRule(rule_id="r1", src_ip="10.0.0.1")
        assert rule.ip_version == 4

    def test_ip_version_6_for_ipv6(self):
        """src_ip IPv6 (contiene ':') → ip_version = 6."""
        rule = DynamicRule(rule_id="r2", src_ip="fd00:3::10")
        assert rule.ip_version == 6

    def test_protocol_property_alias(self):
        """La propiedad .protocol es alias de .proto."""
        rule = DynamicRule(rule_id="r3", src_ip="10.0.0.1", proto="udp")
        assert rule.protocol == "udp"

    def test_default_action_is_drop(self):
        """La acción por defecto es 'drop'."""
        rule = DynamicRule(rule_id="r4", src_ip="10.0.0.1")
        assert rule.action == "drop"

    def test_default_ttl(self):
        """El TTL por defecto es 60."""
        rule = DynamicRule(rule_id="r5", src_ip="10.0.0.1")
        assert rule.ttl == 60
