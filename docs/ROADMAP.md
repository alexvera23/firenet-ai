# Guía de Ejecución Paso a Paso: FireNet-AI (Plan de 2 Semanas)

Esta guía condensa la arquitectura, desarrollo y experimentación de **FireNet-AI** en un plan operativo comprimido de 14 días.

##  Resumen del Cronograma de 14 Días

| Semana | Días | Enfoque Principal | Entregable Clave | 
| ----- | ----- | ----- | ----- | 
| **Semana 1** | Días 1-2 | Entorno, Red y Captura Base | Topología funcional y script de captura/features | 
|  | Días 3-4 | Generación de Datos y Modelado ML | Dataset procesado y modelos entrenados (RF, XGB, MLP) | 
|  | Días 5-7 | Motor de Políticas e Inferencia en Tiempo Real | Core de decisión, evaluador de reglas y dry-run | 
| **Semana 2** | Días 8-9 | Integración con Firewall (nftables) y Rollback | Prototipo extremo a extremo con reglas temporales (TTL) | 
|  | Días 10-11 | Ejecución de Escenarios E0-E6 y Colecta de Métricas | Matriz de datos crudos (estático vs adaptativo) | 
|  | Días 12-13 | Pruebas de Ablación, Análisis Estadístico y Monitoreo | Visualización, pruebas de hipótesis y métricas de red | 
|  | Día 14 | Consolidación del Repositorio y Reporte Final | Paquete reproducible y manuscrito técnico | 

##  Estructura del Repositorio de Código

Para garantizar la modularidad exigida por la arquitectura, cree la siguiente estructura de carpetas en el sistema:

```
mkdir -p firenet-ai/{docs,lab/{topology,firewall-baseline,traffic-scenarios},data/{raw,processed,schemas},src/{capture,features,ml,policy,firewall,monitoring},models,experiments/{configs,runs,analysis},tests}
cd firenet-ai

```

##  FASE 1: Entorno, Red y Extracción de Datos (Días 1 - 2)

### Día 1: Configuración de la Topología de Red y Firewall Base

**Objetivo:** Crear un entorno virtualizado aislado (mediante Linux Namespaces o Mininet) con un nodo Cliente, Attacker, Gateway (FireNet-AI) y Target.

1. **Crear namespaces de red (Entorno Aislado):**

   ```
   # Crear namespaces
   sudo ip netns add client
   sudo ip netns add attacker
   sudo ip netns add gateway
   sudo ip netns add target
   
   # Crear interfaces VETH de conexión
   sudo ip link add veth-c-gw type veth peer name veth-gw-c
   sudo ip link add veth-a-gw type veth peer name veth-gw-a
   sudo ip link add veth-gw-t type veth peer name veth-t-gw
   
   # Asignar interfaces a namespaces
   sudo ip link set veth-c-gw netns client
   sudo ip link set veth-gw-c netns gateway
   sudo ip link set veth-a-gw netns attacker
   sudo ip link set veth-gw-a netns gateway
   sudo ip link set veth-gw-t netns gateway
   sudo ip link set veth-t-gw netns target
   
   # Configurar direcciones IPv4 e IPv6 (Ejemplo segmento cliente/gateway)
   sudo ip netns exec client ip addr add 10.0.1.10/24 dev veth-c-gw
   sudo ip netns exec client ip addr add fd00:1::10/64 dev veth-c-gw
   sudo ip netns exec client ip link set veth-c-gw up
   
   sudo ip netns exec gateway ip addr add 10.0.1.1/24 dev veth-gw-c
   sudo ip netns exec gateway ip addr add fd00:1::1/64 dev veth-gw-c
   sudo ip netns exec gateway ip link set veth-gw-c up
   
   # Habilitar forwarding en Gateway
   sudo ip netns exec gateway sysctl -w net.ipv4.ip_forward=1
   sudo ip netns exec gateway sysctl -w net.ipv6.conf.all.forwarding=1
   
   ```

2. **Configurar `nftables` Estático (Línea Base):**
   Crear la tabla base en el nodo `gateway`:

   ```
   sudo ip netns exec gateway nft add table inet firenet
   sudo ip netns exec gateway nft add chain inet firenet input '{ type filter hook input priority 0; policy accept; }'
   sudo ip netns exec gateway nft add chain inet firenet forward '{ type filter hook forward priority 0; policy accept; }'
   sudo ip netns exec gateway nft add chain inet firenet dynamic_rules '{ type filter hook forward priority -1; policy accept; }'
   
   ```

### Día 2: Capturador de Tráfico y Extractor de Características

**Objetivo:** Desarrollar el módulo en Python que agrega tráfico en ventanas temporales de flujos bidireccionales y calcula el vector de variables.

Crear el archivo `src/features/extractor.py`:

```
import time
from collections import defaultdict
import numpy as np

class FlowExtractor:
    def __init__(self, window_seconds=2.0):
        self.window_seconds = window_seconds
        self.flows = defaultdict(lambda: {
            'start_time': None, 'last_time': None,
            'pkts_fwd': 0, 'pkts_rev': 0,
            'bytes_fwd': 0, 'bytes_rev': 0,
            'tcp_flags': set(), 'src_port': 0, 'dst_port': 0,
            'ip_version': 4, 'protocol': 6
        })

    def process_packet(self, pkt_metadata):
        # Key: (src_ip, dst_ip, src_port, dst_port, proto)
        flow_key = pkt_metadata['key']
        now = pkt_metadata['timestamp']
        
        flow = self.flows[flow_key]
        if flow['start_time'] is None:
            flow['start_time'] = now
            flow['src_port'] = pkt_metadata.get('src_port', 0)
            flow['dst_port'] = pkt_metadata.get('dst_port', 0)
            flow['ip_version'] = pkt_metadata['ip_version']
            flow['protocol'] = pkt_metadata['protocol']

        flow['last_time'] = now
        
        if pkt_metadata['is_forward']:
            flow['pkts_fwd'] += 1
            flow['bytes_fwd'] += pkt_metadata['length']
        else:
            flow['pkts_rev'] += 1
            flow['bytes_rev'] += pkt_metadata['length']

        if 'tcp_flags' in pkt_metadata:
            flow['tcp_flags'].update(pkt_metadata['tcp_flags'])

    def extract_features(self):
        dataset_rows = []
        now = time.time()
        keys_to_remove = []

        for key, f in self.flows.items():
            duration = max(f['last_time'] - f['start_time'], 0.001)
            total_pkts = f['pkts_fwd'] + f['pkts_rev']
            total_bytes = f['bytes_fwd'] + f['bytes_rev']
            
            features = {
                'ip_version': f['ip_version'],
                'protocol': f['protocol'],
                'duration': duration,
                'packets': total_pkts,
                'bytes': total_bytes,
                'pps': total_pkts / duration,
                'bps': (total_bytes * 8) / duration,
                'pkts_fwd': f['pkts_fwd'],
                'pkts_rev': f['pkts_rev'],
                'ratio_pkts': f['pkts_fwd'] / max(f['pkts_rev'], 1),
                'mean_pkt_size': total_bytes / max(total_pkts, 1),
                'src_port': f['src_port'],
                'dst_port': f['dst_port'],
                'syn_flag': 1 if 'SYN' in f['tcp_flags'] else 0
            }
            dataset_rows.append((key, features))
            
            # Limpiar flujos inactivos
            if now - f['last_time'] > self.window_seconds:
                keys_to_remove.append(key)

        for k in keys_to_remove:
            del self.flows[k]

        return dataset_rows

```

##  FASE 2: Generación de Datasets y Entrenamiento ML (Días 3 - 4)

### Día 3: Generación de Escenarios de Tráfico y Etiquetado

**Objetivo:** Ejecutar scripts de ataque y benignos controlados para recolectar el dataset inicial.

1. **Scripts de simulación (`lab/traffic-scenarios/`):**

   * **Benigno (E0):** Navegación HTTP, SSH legítimo, tráfico ICMP ping.

   * **Escaneo (E1):** `nmap -sS -p 1-1000 10.0.2.10`

   * **Fuerza Bruta (E2):** `hydra -l user -P passlist.txt ssh://10.0.2.10`

   * **DDoS Controlado (E3):** `hping3 --flood --rand-source -p 80 10.0.2.10`

   * **Exfiltración (E4):** Transferencia masiva continua por Netcat en ráfagas.

2. **Ejecutar capturas y guardar en `data/processed/dataset_v1.csv`:**
   Asegúrese de agregar las columnas contextuales: `flow_id`, `run_id`, `scenario_id`, y la etiqueta `label` (0 = Benigno, 1 = Malicioso).

### Día 4: Entrenamiento y Evaluación Comparativa de Modelos

**Objetivo:** Entrenar Random Forest, XGBoost y MLP usando scikit-learn/xgboost. Evaluar con división por *ejecución/escenario* (evitando *data leakage*).

Crear script `src/ml/train.py`:

```
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score, roc_auc_score

def train_and_evaluate():
    # Cargar datos
    df = pd.read_csv('data/processed/dataset_v1.csv')
    
    # Separación por escenario para evitar data leakage
    train_df = df[df['scenario_id'].isin(['E0', 'E1', 'E2', 'E3'])]
    test_df = df[df['scenario_id'].isin(['E4', 'E5'])]

    features = ['ip_version', 'protocol', 'duration', 'packets', 'bytes', 
                'pps', 'bps', 'pkts_fwd', 'pkts_rev', 'ratio_pkts', 
                'mean_pkt_size', 'src_port', 'dst_port', 'syn_flag']
    
    X_train, y_train = train_df[features], train_df['label']
    X_test, y_test = test_df[features], test_df['label']

    models = {
        'RandomForest': RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42),
        'XGBoost': XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42),
        'MLP': MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=42)
    }

    best_model = None
    best_f1 = 0.0

    for name, model in models.items():
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        probs = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else preds
        
        f1 = f1_score(y_test, preds)
        prec = precision_score(y_test, preds)
        rec = recall_score(y_test, preds)
        
        print(f"=== {name} ===")
        print(f"Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}")
        
        if f1 > best_f1:
            best_f1 = f1
            best_model = (name, model)

    print(f"\nModelo Seleccionado: {best_model[0]}")
    joblib.dump(best_model[1], 'models/firenet_best_model.pkl')

if __name__ == '__main__':
    train_and_evaluate()

```

## 🛡️ FASE 3: Motor de Políticas y Modulo Firewall (Días 5 - 9)

### Días 5 - 7: Motor de Políticas de Seguridad (Dry-Run)

**Objetivo:** Desarrollar la lógica intermediary entre la predicción de IA y la ejecución de la regla para evitar falsos bloqueos.

Crear `src/policy/engine.py`:

```
import time

class PolicyEngine:
    def __init__(self, config):
        self.min_score = config.get('min_score}', 0.85)
        self.ttl_default = config.get('ttl_seconds', 60)
        self.protected_ips = set(config.get('protected_ips', ['10.0.1.1', '10.0.2.10']))
        self.history = {} # Guardar contador de apariciones para persistencia

    def evaluate(self, flow_key, prediction_score, flow_data):
        src_ip = flow_key[0]
        dst_ip = flow_key[1]

        # 1. Verificación de Lista Protegida (Allowlist)
        if src_ip in self.protected_ips or dst_ip in self.protected_ips:
            return {'action': 'ALERT', 'reason': 'Protected entity involved'}

        # 2. Umbral de Confianza
        if prediction_score < self.min_score:
            return {'action': 'OBSERVE', 'reason': 'Score below threshold'}

        # 3. Control de Persistencia (Evitar falsos positivos aislados)
        self.history[src_ip] = self.history.get(src_ip, 0) + 1
        if self.history[src_ip] < 2:
            return {'action': 'ALERT', 'reason': 'Awaiting persistence validation'}

        # 4. Generación de Regla Candidata
        candidate_rule = {
            'action': 'APPLY',
            'src_ip': src_ip,
            'dst_port': flow_data['dst_port'],
            'protocol': 'tcp' if flow_data['protocol'] == 6 else 'udp',
            'ip_version': flow_data['ip_version'],
            'ttl': self.ttl_default,
            'reason': f"AI Detection (Score: {prediction_score:.2f})"
        }
        return candidate_rule

```

### Días 8 - 9: Traductor y Ejecutor nftables con TTL y Rollback

**Objetivo:** Aplicar reglas en el firewall usando `nftables` e implementar su remoción automática.

Crear `src/firewall/nft_executor.py`:

```
import subprocess
import threading
import time

class NftExecutor:
    def __init__(self, table_name="inet firenet", chain_name="dynamic_rules"):
        self.table_name = table_name
        self.chain_name = chain_name
        self.active_rules = {}

    def apply_rule(self, rule_spec):
        ip_ver = "ip" if rule_spec['ip_version'] == 4 else "ip6"
        src_ip = rule_spec['src_ip']
        port = rule_spec['dst_port']
        proto = rule_spec['protocol']
        ttl = rule_spec['ttl']

        rule_cmd = f"{ip_ver} saddr {src_ip} {proto} dport {port} drop"
        full_cmd = f"nft add rule {self.table_name} {self.chain_name} {rule_cmd}"

        try:
            # Aplicar en nftables
            subprocess.run(full_cmd, shell=True, check=True)
            print(f"[FIREWALL] Regla Aplicada: {full_cmd}")

            # Programar expiración (TTL)
            timer = threading.Timer(ttl, self.revoke_rule, args=[rule_cmd])
            timer.start()
            self.active_rules[src_ip] = timer
            return True
        except subprocess.CalledProcessError as e:
            print(f"[ERROR FIREWALL] Fallo al aplicar regla: {e}")
            return False

    def revoke_rule(self, rule_cmd):
        # Rollback / Expiración
        print(f"[FIREWALL] Revocando regla por TTL: {rule_cmd}")
        # En nftables real, se remueve mediante handle o limpiando el set dinámico
        # Para prototipo rápido, flush de la cadena dinámicas al expirar
        subprocess.run(f"nft flush chain {self.table_name} {self.chain_name}", shell=True)

    def emergency_rollback(self):
        """Limpieza total de emergencia."""
        subprocess.run(f"nft flush chain {self.table_name} {self.chain_name}", shell=True)
        print("[EMERGENCY] Todas las reglas dinámicas han sido revocadas.")

```

##  FASE 4: Experimentación y Recolección de Datos (Días 10 - 11)

### Ejecución del Protocolo de Validación (Escenarios E0 a E6)

Se deben realizar dos corridas por cada escenario: **Condición A (Estático)** y **Condición B (Adaptativo FireNet-AI)**.

```
# Ejemplo de Ejecución Automática por Escenario
python src/main.py --mode adaptative --scenario E1_Scan --duration 300 --run_id RUN_001
python src/main.py --mode static --scenario E1_Scan --duration 300 --run_id RUN_002

```

**Formato del Archivo de Registro por Corrida (`experiments/runs/RUN_001.json`):**

```
{
  "run_id": "RUN_001",
  "scenario_id": "E1_Scan",
  "condition": "FireNet-AI",
  "start_time": 1772700000,
  "metrics": {
    "tp": 142,
    "tn": 850,
    "fp": 3,
    "fn": 5,
    "time_to_block_ms": 420.5,
    "avg_latency_ms": 1.12,
    "throughput_mbps": 94.5,
    "cpu_percent": 12.4,
    "ram_mb": 145.2,
    "rules_applied": 4,
    "rules_revoked": 4
  }
}

```

## 🔬 FASE 5: Análisis Estadístico, Ablación y Cierre (Días 12 - 14)

### Día 12: Pruebas de Ablación

Realizar variaciones del sistema para determinar la contribución de cada componente:

1. **Sin variables temporales (A1):** Remover `pps` y `bps`.

2. **Sin motor de persistencia (A3):** Evaluar impacto de aplicar reglas al primer positivo de la IA.

3. **Variación del Umbral (A4):** Evaluar rendimiento del sistema con umbrales de decisión $T \in \{0.6, 0.75, 0.90, 0.98\}$.

### Día 13: Análisis Estadístico en Python

Crear el archivo `experiments/analysis/stats.py` para comparar el modelo adaptativo contra el estático:

```
import json
import scipy.stats as stats
import pandas as pd

def run_hypothesis_tests(results_df):
    # Comparar tiempo de bloqueo entre estático y adaptativo
    static_ttb = results_df[results_df['condition'] == 'Static']['time_to_block_ms']
    ai_ttb = results_df[results_df['condition'] == 'FireNet-AI']['time_to_block_ms']

    # Test de Shapiro-Wilk (Normalidad)
    _, p_norm = stats.shapiro(ai_ttb)

    if p_norm > 0.05:
        # Distribución Normal -> Paired t-test
        stat, p_val = stats.ttest_rel(static_ttb, ai_ttb)
        test_name = "t-test pareado"
    else:
        # Distribución No Normal -> Wilcoxon Signed-Rank Test
        stat, p_val = stats.wilcoxon(static_ttb, ai_ttb)
        test_name = "Wilcoxon"

    print(f"Prueba Aplicada: {test_name}")
    print(f"Estadístico: {stat:.4f} | p-value: {p_val:.4e}")
    
    if p_val < 0.05:
        print("Resultado: Rechazamos H0. Mejora estadísticamente significativa.")
    else:
        print("Resultado: No se rechaza H0.")

```

### Día 14: Definición de Terminado (Checklist de Entrega)

Para dar por concluido el proyecto de manera exitosa, asegúrese de completar la siguiente lista de verificación:

* \[ \] **Línea Base Reprocesable:** Configuración de `nftables` estático guardada y aislada.

* \[ \] **Topología Operativa:** Entorno de red IPv4 e IPv6 ejecutado con éxito bajo `netns` o mininet.

* \[ \] **Modelos Entrenados:** Artefacto `.pkl` con Random Forest, XGBoost y MLP guardados en la carpeta `/models`.

* \[ \] **Evaluación Anti-Leakage:** Separación del dataset por escenarios en la etapa de entrenamiento.

* \[ \] **Auditoría e Historial:** Formato de logs completo con vinculación de evento $\rightarrow$ predicción $\rightarrow$ regla aplicada.

* \[ \] **Seguridad Operativa:** Lista de IPs/Servicios protegidos validada en pruebas unitarias.

* \[ \] **Mecanismo Rollback:** Verificación de expiración automática de reglas por TTL.

* \[ \] **Resultados Estadísticos:** Fórmulas de Accuracy, FPR, FNR, Recall y pruebas de hipótesis exportadas a tablas.

* \[ \] **Repositorio Documentado:** Código fuente versionado y acompañado por el manuscrito final.