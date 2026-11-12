"""
FireNet-AI - Ejecutor y Traductor de Reglas para nftables (NftablesExecutor)
Conforme a Fase 3 (Días 8-9 del ROADMAP y PROMPT1):
  - Envuelve llamadas CLI a `nft` mediante argumentos tokenizados (NO shell=True).
  - Tabla destino: inet firenet_table | Cadena: dynamic_rules.
  - Inyección de regla drop con comentario `firenet_id=<id> timeout=<ttl>s`.
  - Expiración automática / TTL con timers y método `revoke_rule(rule_id)`.
  - Método `flush_dynamic_rules()` para restablecimiento de línea base.
  - Método `list_active_rules()` que analiza formato JSON (`nft -j list chain ...`).
  - Soporte de network namespaces (netns) de Linux y compatibilidad con Arch Linux / Fish shell.
"""

import os
import re
import json
import logging
import threading
import subprocess
from typing import Optional, List, Dict, Any, Callable
from pathlib import Path

from src.models import DynamicRule

logger = logging.getLogger(__name__)


class NftablesExecutor:
    def __init__(
        self,
        table: str = "firenet",
        family: str = "inet",
        chain: str = "dynamic_rules",
        netns: Optional[str] = None,
        use_sudo: Optional[bool] = None,
        dry_run: bool = False,
        use_unshare: bool = False,
        auto_expire: bool = True,
        on_expire_callback: Optional[Callable[[str], None]] = None,
        on_revoke_callback: Optional[Callable[[str], None]] = None,
    ):
        self.table = table
        self.family = family
        self.chain = chain
        self.netns = netns
        self.dry_run = dry_run
        self.use_unshare = use_unshare
        self.auto_expire = auto_expire
        self.on_expire_callback = on_expire_callback
        self.on_revoke_callback = on_revoke_callback

        # Configuración de sudo
        if use_sudo is None:
            # Si no somos root y necesitamos netns o modificar firewall del host, usar sudo
            self.use_sudo = (os.geteuid() != 0) and not self.use_unshare and not self.dry_run
        else:
            self.use_sudo = use_sudo

        # Control de reglas activas y temporizadores de expiración
        self.active_rules: Dict[str, DynamicRule] = {}
        self.rule_handles: Dict[str, int] = {}
        self._timers: Dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

        # Historial para auditoría y pruebas (dry_run)
        self.command_history: List[List[str]] = []
        self._simulated_rules: List[Dict[str, Any]] = []
        self._simulated_next_handle: int = 100

    def _build_command_prefix(self) -> List[str]:
        """Construye el prefijo de ejecución (sudo, netns, unshare)."""
        prefix = []
        if self.use_unshare:
            prefix.extend(["unshare", "-r", "-n"])
        elif self.netns:
            if self.use_sudo:
                prefix.extend(["sudo", "ip", "netns", "exec", self.netns])
            else:
                prefix.extend(["ip", "netns", "exec", self.netns])
        elif self.use_sudo:
            prefix.extend(["sudo"])

        return prefix

    def _execute(self, nft_args: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """
        Ejecuta un comando de nftables de forma segura usando tokens.
        Garantiza que NUNCA se use concatenación de strings con shell=True.
        """
        full_command = self._build_command_prefix() + nft_args
        self.command_history.append(full_command)
        cmd_str = " ".join(full_command)
        logger.debug(f"[NFT EXEC] {cmd_str}")

        if self.dry_run:
            logger.info(f"[NFT DRY-RUN] {cmd_str}")
            return subprocess.CompletedProcess(
                args=full_command,
                returncode=0,
                stdout="",
                stderr=""
            )

        try:
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                check=check
            )
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"[NFT ERROR] Fallo al ejecutar {cmd_str}: {e.stderr}")
            raise

    def ensure_chain_exists(self) -> bool:
        """
        Asegura idempotentemente la existencia de la tabla y la cadena dinámica regular en nftables.
        """
        try:
            self._execute(["nft", "add", "table", self.family, self.table], check=True)
            # Declarar como cadena regular (el salto viene desde base_forward en nftables.conf)
            self._execute(
                ["nft", "add", "chain", self.family, self.table, self.chain],
                check=True
            )
            logger.info(f"[NFT] Tabla {self.family} {self.table} y cadena {self.chain} inicializadas.")
            return True
        except Exception as e:
            logger.warning(f"[NFT] Aviso al verificar tabla/cadena: {e}")
            return False

    def apply_rule(self, rule: DynamicRule) -> bool:
        """
        Inyecta una regla dinámica de tipo drop en nftables con comentario identificador
        y programa su tiempo de vida (TTL) si auto_expire está activo.
        """
        ip_ver = "ip" if rule.ip_version == 4 else "ip6"
        proto = rule.protocol.lower() if rule.protocol else "tcp"
        comment_str = f"firenet_id={rule.rule_id} timeout={rule.ttl}s"

        tokens = [
            "nft", "add", "rule",
            self.family, self.table, self.chain,
            ip_ver, "saddr", str(rule.src_ip)
        ]

        # Puerto destino y protocolo (sintaxis válida para nftables inet)
        if rule.dst_port and rule.dst_port > 0:
            if proto in ("tcp", "udp"):
                tokens.extend([proto, "dport", str(rule.dst_port)])
        elif proto in ("tcp", "udp"):
            tokens.extend(["meta", "l4proto", proto])

        # Comillas dobles literales alrededor del comentario para el lexer de nft
        tokens.extend([rule.action.lower(), "comment", f'"{comment_str}"'])

        with self._lock:
            try:
                if self.dry_run:
                    self._execute(tokens, check=True)
                    handle = self._simulated_next_handle
                    self._simulated_next_handle += 1
                    self.rule_handles[rule.rule_id] = handle
                    self._simulated_rules.append({
                        "handle": handle,
                        "comment": comment_str,
                        "rule_id": rule.rule_id,
                        "src_ip": rule.src_ip,
                        "dst_port": rule.dst_port,
                        "protocol": proto,
                        "action": rule.action,
                    })
                else:
                    self._execute(tokens, check=True)

                self.active_rules[rule.rule_id] = rule

                # Programar expiración automática por TTL
                if self.auto_expire and rule.ttl > 0:
                    timer = threading.Timer(
                        float(rule.ttl),
                        self._handle_rule_timeout,
                        args=[rule.rule_id]
                    )
                    timer.daemon = True
                    self._timers[rule.rule_id] = timer
                    timer.start()

                logger.info(
                    f"[FIREWALL APPLY] Regla aplicada: ID={rule.rule_id} "
                    f"Src={rule.src_ip} DstPort={rule.dst_port} TTL={rule.ttl}s"
                )
                return True

            except Exception as e:
                logger.error(f"[FIREWALL ERROR] No se pudo aplicar regla {rule.rule_id}: {e}")
                return False

    def _handle_rule_timeout(self, rule_id: str) -> None:
        """Manejador interno invocado cuando expira el TTL de una regla."""
        logger.info(f"[FIREWALL TTL] Expiró TTL para regla: {rule_id}")
        self.revoke_rule(rule_id)
        if self.on_expire_callback:
            try:
                self.on_expire_callback(rule_id)
            except Exception as e:
                logger.error(f"[CALLBACK ERROR] Error en on_expire_callback: {e}")

    def revoke_rule(self, rule_id: str) -> bool:
        """
        Elimina la regla dinámica especificada por rule_id o identificador.
        Cancela el timer asociado y remueve la regla de nftables por su handle.
        """
        with self._lock:
            # Cancelar timer si estaba activo
            timer = self._timers.pop(rule_id, None)
            if timer and timer.is_alive():
                timer.cancel()

            rule = self.active_rules.pop(rule_id, None)

            if self.dry_run:
                self._simulated_rules = [
                    r for r in self._simulated_rules if r.get("rule_id") != rule_id
                ]
                tokens = [
                    "nft", "delete", "rule",
                    self.family, self.table, self.chain,
                    "handle", str(self.rule_handles.get(rule_id, 0))
                ]
                self._execute(tokens, check=False)
                if self.on_revoke_callback:
                    self.on_revoke_callback(rule_id)
                logger.info(f"[FIREWALL REVOKE (DRY-RUN)] Regla {rule_id} revocada.")
                return True

            # Buscar handle real en nftables
            target_handle = self.rule_handles.get(rule_id)
            if target_handle is None:
                active_list = self.list_active_rules()
                for item in active_list:
                    if item.get("rule_id") == rule_id:
                        target_handle = item.get("handle")
                        break

            if target_handle is None:
                logger.warning(f"[FIREWALL REVOKE] No se encontró handle para regla {rule_id}")
                return False

            try:
                tokens = [
                    "nft", "delete", "rule",
                    self.family, self.table, self.chain,
                    "handle", str(target_handle)
                ]
                self._execute(tokens, check=True)
                self.rule_handles.pop(rule_id, None)

                if self.on_revoke_callback:
                    try:
                        self.on_revoke_callback(rule_id)
                    except Exception as e:
                        logger.error(f"[CALLBACK ERROR] Error en on_revoke_callback: {e}")

                logger.info(f"[FIREWALL REVOKE] Regla {rule_id} (handle {target_handle}) revocada.")
                return True

            except Exception as e:
                logger.error(f"[FIREWALL ERROR] Error al revocar regla {rule_id} (handle {target_handle}): {e}")
                return False

    def flush_dynamic_rules(self) -> bool:
        """
        Elimina todas las reglas dinámicas activas, restableciendo el estado base.
        Cancela todos los temporizadores en curso.
        """
        with self._lock:
            # Cancelar todos los temporizadores
            for r_id, timer in list(self._timers.items()):
                if timer and timer.is_alive():
                    timer.cancel()
            self._timers.clear()
            self.active_rules.clear()
            self.rule_handles.clear()

            if self.dry_run:
                self._simulated_rules.clear()
                tokens = ["nft", "flush", "chain", self.family, self.table, self.chain]
                self._execute(tokens, check=False)
                logger.info("[FIREWALL FLUSH (DRY-RUN)] Cadena dynamic_rules limpiada.")
                return True

            try:
                tokens = ["nft", "flush", "chain", self.family, self.table, self.chain]
                self._execute(tokens, check=True)
                logger.info(f"[FIREWALL FLUSH] Todas las reglas dinámicas de {self.chain} han sido vaciadas.")
                return True
            except Exception as e:
                logger.error(f"[FIREWALL ERROR] Fallo al vaciar cadena {self.chain}: {e}")
                return False

    def list_active_rules(self) -> List[Dict[str, Any]]:
        """
        Analiza las reglas dinámicas actuales en formato JSON:
        `nft -j list chain inet firenet_table dynamic_rules`
        Retorna una lista estructurada con metadatos de cada regla.
        """
        if self.dry_run:
            return list(self._simulated_rules)

        tokens = ["nft", "-j", "list", "chain", self.family, self.table, self.chain]
        try:
            res = self._execute(tokens, check=True)
            if not res.stdout.strip():
                return []

            data = json.loads(res.stdout)
            rules_found = []

            for item in data.get("nftables", []):
                if "rule" in item:
                    r_data = item["rule"]
                    handle = r_data.get("handle")
                    comment = r_data.get("comment", "")

                    # Extraer rule_id de "firenet_id=<id> ..."
                    rule_id = None
                    if comment:
                        match = re.search(r"firenet_id=([^\s,]+)", comment)
                        if match:
                            rule_id = match.group(1)

                    rules_found.append({
                        "handle": handle,
                        "rule_id": rule_id,
                        "comment": comment,
                        "expr": r_data.get("expr", []),
                        "raw": r_data
                    })

                    if rule_id and handle:
                        self.rule_handles[rule_id] = handle

            return rules_found

        except Exception as e:
            logger.warning(f"[NFT LIST WARNING] No se pudieron listar reglas: {e}")
            return []
