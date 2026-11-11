#!/usr/bin/env python3
"""
Pruebas unitarias para el Motor de Políticas y el Ejecutor Nftables (Fase 3).
"""

import pytest
from unittest.mock import MagicMock, patch
from src.policy.engine import PolicyEngine, ActionState
from src.firewall.executor import NftablesExecutor, DynamicRule


class TestPolicyEngine:
    @pytest.fixture
    def engine(self):
        protected_ips = {"192.168.10.1", "192.168.20.1", "fd00:10::1", "fd00:20::1"}
        return PolicyEngine(
            min_score=0.85,
            protected_ips=protected_ips,
            protected_ports={22, 80},
            max_rules_per_min=10,
            cooldown_seconds=5
        )

    def test_observe_under_threshold(self, engine):
        action, _ = engine.evaluate(
            src_ip="10.0.0.5",
            dst_ip="192.168.20.2",
            score=0.50,
            proto="TCP",
            dst_port=443
        )
        assert action == ActionState.OBSERVE

    def test_allowlist_protection_ip(self, engine):
        action, _ = engine.evaluate(
            src_ip="192.168.10.1",
            dst_ip="192.168.20.2",
            score=0.99,
            proto="TCP",
            dst_port=8080
        )
        assert action == ActionState.ALERT

    def test_persistence_requirement(self, engine):
        src_ip = "192.168.10.50"
        act1, _ = engine.evaluate(src_ip, "192.168.20.2", 0.90, "TCP", 8080)
        assert act1 == ActionState.ALERT

        act2, rule = engine.evaluate(src_ip, "192.168.20.2", 0.92, "TCP", 8080)
        assert act2 == ActionState.APPLY
        assert rule is not None
        assert rule.src_ip == src_ip

    def test_volumetric_immediate_apply(self, engine):
        src_ip = "10.0.0.99"
        action, rule = engine.evaluate(
            src_ip=src_ip,
            dst_ip="192.168.20.2",
            score=0.98,
            proto="UDP",
            dst_port=9999,
            is_volumetric=True
        )
        assert action == ActionState.APPLY
        assert rule.ttl == 120


class TestNftablesExecutor:
    @pytest.fixture
    def executor(self):
        return NftablesExecutor(table="firenet_table", chain="dynamic_rules", dry_run=True)

    def test_apply_rule_dry_run(self, executor):
        rule = DynamicRule(
            rule_id="rule_test_01",
            src_ip="192.168.10.55",
            dst_ip="192.168.20.2",
            proto="tcp",
            dst_port=80,
            ttl=60,
            reason="PortScan"
        )
        success = executor.apply_rule(rule)
        assert success is True
        assert len(executor.command_history) > 0
        cmd = executor.command_history[-1]
        assert "drop" in cmd
        assert "comment" in cmd