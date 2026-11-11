Rol: Ingeniero sénior de seguridad de redes y sistemas (Python).
Tarea: Implementar el motor de políticas (*Policy Engine*), el ejecutor de `nftables` y el flujo de inferencia en tiempo real (*Live Inference Pipeline*) para FireNet-AI (Fase 3).

Contexto:
Hemos entrenado un modelo MLP, guardado en `models/firenet_best_model.pkl`, junto con sus metadatos de escalado en `models/model_metadata.json`.
Operamos dentro de espacios de nombres de red (*network namespaces*) de Arch Linux (`ns-gateway` contiene `nftables`).

Requisitos:
1. Crear `src/policy/engine.py`:
- Clase `PolicyEngine`: Implementa transiciones de estado (OBSERVE, ALERT, PROPOSE, APPLY, EXPIRE, REVOKE). 
- Verificación de un umbral mínimo de puntuación (por defecto, T = 0,85). 
- Aplicación de una lista blanca (*allowlist*): nunca bloquear las IP `192.168.10.1`, `192.168.20.1`, `fd00:10::1`, `fd00:20::1`, ni los puertos protegidos 22/80 (si están marcados como tales). 
- Verificación de persistencia: requiere al menos 2 alertas consecutivas de alta confianza para ataques de bajo volumen antes de proponer una acción de tipo APPLY; para ataques volumétricos (DDoS), basta con 1 alerta. 
- Limitación de la tasa de creación de reglas (por ejemplo, un máximo de 10 reglas dinámicas por minuto). 
- Periodo de espera (*cooldown*) por IP de origen para evitar la oscilación o inestabilidad (*flapping*) de las reglas.

2. Crear `src/firewall/executor.py`:
- Clase `NftablesExecutor`: Envuelve las llamadas a la CLI de `nft` mediante el módulo `subprocess` de Python, utilizando argumentos tokenizados (prohibida la concatenación de cadenas para evitar la inyección de comandos). 
- Tabla destino: `inet firenet_table`; cadena (*chain*): `dynamic_rules`. 
- Método `apply_rule(rule: DynamicRule)`: Inyecta una regla de tipo `drop` en `nftables` con el comentario `firenet_id=<id>` y un tiempo de expiración/TTL explícito (por ejemplo, `timeout 60s`). 
- Método `revoke_rule(rule_id: str)`: Elimina la regla dinámica especificada. - Método `flush_dynamic_rules()`: Elimina todas las reglas dinámicas activas, restableciendo el estado base.
- Método `list_active_rules()`: Analiza las reglas dinámicas actuales en formato JSON (`nft -j list chain inet firenet_table dynamic_rules`).

3. Crear `src/pipeline.py`:
- Integra la captura en tiempo real (utilizando la lógica de extracción de características de `sniffer.py`), la inferencia mediante `firenet_best_model.pkl`, la evaluación a través de `PolicyEngine` y la aplicación de medidas mediante `NftablesExecutor`.
- Implementa un registro (logging) estructurado en formato JSON en `logs/audit.jsonl` para cada evaluación (campos: `timestamp`, `run_id`, `flow_id`, `model_version`, `score`, `policy_action`, `rule_id`, `ttl`, `apply_status`).

4. Crear pruebas unitarias y de integración en `tests/test_policy_firewall.py` utilizando `pytest`.

Asegurar la compatibilidad con el shell Fish y el manejo correcto de los contextos de ejecución `netns` (espacios de nombres de red) en Linux. Generar código completo y ejecutable, sin marcadores de posición (placeholders).