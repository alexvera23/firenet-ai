#!/usr/bin/env python3
"""
FireNet-AI - Entrenamiento y Evaluación Comparativa de Modelos ML (Fase 2: Día 4)
Conforme a docs/ROADMAP.md:
  - Entrena Random Forest, XGBoost y MLP usando scikit-learn y xgboost.
  - Particionamiento anti-leakage por escenario:
      * Entrenamiento : E0 (Benigno), E1 (Port Scan), E2 (Bruteforce), E3 (DDoS)
      * Evaluación    : E4 (Exfiltración), E5 (Stealth Probe / Low-and-Slow)
  - Métricas de desempeño: Precision, Recall, F1-Score, ROC-AUC, FPR, FNR, latencia de inferencia.
  - Guarda el mejor modelo serializado en models/firenet_best_model.pkl y metadatos en models/model_metadata.json.
"""

import os
import sys
import json
import time
import pickle
import argparse
from pathlib import Path

# Configurar path raíz del proyecto
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score
)

DEFAULT_DATASET = PROJECT_ROOT / "data" / "processed" / "dataset_v1.csv"
MODEL_OUTPUT_DIR = PROJECT_ROOT / "models"
EXPERIMENTS_DIR = PROJECT_ROOT / "experiments" / "runs"

FEATURE_COLUMNS = [
    'ip_version',
    'protocol',
    'duration',
    'packets',
    'bytes',
    'pps',
    'bps',
    'pkts_fwd',
    'pkts_rev',
    'ratio_pkts',
    'mean_pkt_size',
    'src_port',
    'dst_port',
    'syn_flag'
]


def load_dataset(dataset_path):
    """Carga y valida el archivo CSV procesado de flujos."""
    path = Path(dataset_path)
    if not path.exists():
        raise FileNotFoundError(f"No se encontró el dataset en '{path}'. Ejecute primero la recolección.")

    df = pd.read_csv(path)
    print(f"[+] Dataset cargado exitosamente desde: {path}")
    print(f"    - Registros totales : {len(df)}")
    print(f"    - Columnas presentes: {list(df.columns)}")

    # Validar columnas requeridas
    missing = [c for c in FEATURE_COLUMNS + ['label', 'scenario_id'] if c not in df.columns]
    if missing:
        raise ValueError(f"Faltan columnas requeridas en el dataset: {missing}")

    return df


def split_data(df, train_scenarios=None, test_scenarios=None):
    """
    Realiza la partición de datos por escenarios para evitar data leakage,
    evaluando la generalización ante vectores de ataque desconocidos (Zero-Day).
    """
    if train_scenarios is None:
        train_scenarios = ['E0', 'E1', 'E2', 'E3']
    if test_scenarios is None:
        test_scenarios = ['E4', 'E5']

    train_df = df[df['scenario_id'].isin(train_scenarios)].copy()
    test_df = df[df['scenario_id'].isin(test_scenarios)].copy()

    if train_df.empty or test_df.empty:
        raise ValueError(f"La partición resultó en conjuntos vacíos. Train: {len(train_df)}, Test: {len(test_df)}")

    X_train = train_df[FEATURE_COLUMNS]
    y_train = train_df['label']

    X_test = test_df[FEATURE_COLUMNS]
    y_test = test_df['label']

    print(f"\n[+] Partición Anti-Leakage por Escenarios:")
    print(f"    * Train Scenarios ({train_scenarios}) : {len(train_df)} flujos (Etiquetas: {dict(y_train.value_counts())})")
    print(f"    * Test Scenarios  ({test_scenarios})  : {len(test_df)} flujos (Etiquetas: {dict(y_test.value_counts())})")

    return X_train, y_train, X_test, y_test, train_df, test_df


def benchmark_latency(model, sample_row, iterations=500):
    """Mide la latencia media de inferencia por flujo en microsegundos."""
    times = []
    # Warm up
    for _ in range(20):
        _ = model.predict(sample_row)

    for _ in range(iterations):
        t0 = time.perf_counter()
        _ = model.predict(sample_row)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1_000_000)  # Microsegundos

    return float(np.mean(times)), float(np.std(times))


def train_and_evaluate(dataset_path=DEFAULT_DATASET):
    MODEL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print(" FIRENET-AI: ENTRENAMIENTO Y EVALUACIÓN COMPARATIVA (FASE 2: DÍA 4)")
    print("=" * 70)

    # 1. Cargar y particionar
    df = load_dataset(dataset_path)
    X_train, y_train, X_test, y_test, train_df, test_df = split_data(df)

    # 2. Definición de Modelos
    models = {
        'RandomForest': RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=4,
            random_state=42,
            n_jobs=-1
        ),
        'XGBoost': XGBClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=6,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            eval_metric='logloss',
            n_jobs=-1
        ),
        'MLP': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', MLPClassifier(
                hidden_layer_sizes=(64, 32),
                max_iter=300,
                activation='relu',
                alpha=0.001,
                random_state=42
            ))
        ])
    }

    results = {}
    best_model_name = None
    best_f1 = -1.0
    best_model_obj = None

    sample_for_bench = X_test.iloc[0:1]

    print("\n" + "=" * 70)
    print(" INICIANDO ENTRENAMIENTO Y EVALUACIÓN COMPARATIVA")
    print("=" * 70)

    for name, model in models.items():
        print(f"\n---> Entrenando {name}...")
        t_start = time.time()
        model.fit(X_train, y_train)
        train_duration = time.time() - t_start

        # Predicciones
        preds = model.predict(X_test)
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X_test)[:, 1]
        elif hasattr(model, "decision_function"):
            probs = model.decision_function(X_test)
        else:
            probs = preds

        # Métricas estándar
        f1 = float(f1_score(y_test, preds, zero_division=0))
        prec = float(precision_score(y_test, preds, zero_division=0))
        rec = float(recall_score(y_test, preds, zero_division=0))
        try:
            auc = float(roc_auc_score(y_test, probs))
        except Exception:
            auc = 0.0

        # Matriz de confusión
        cm = confusion_matrix(y_test, preds)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = [int(v) for v in cm.ravel()]
            fpr = float(fp / max(fp + tn, 1))
            fnr = float(fn / max(fn + tp, 1))
        else:
            tn, fp, fn, tp = 0, 0, 0, 0
            fpr, fnr = 0.0, 0.0

        # Latencia de inferencia
        mean_lat_us, std_lat_us = benchmark_latency(model, sample_for_bench)

        # Importancia de características (si aplica)
        feat_importances = {}
        if hasattr(model, "feature_importances_"):
            for f_name, imp in zip(FEATURE_COLUMNS, model.feature_importances_):
                feat_importances[f_name] = round(float(imp), 4)
        elif hasattr(model, "named_steps") and hasattr(model.named_steps.get('classifier'), "coefs_"):
            # Para MLP, magnitud de pesos de la capa de entrada
            mlp_layer0 = np.abs(model.named_steps['classifier'].coefs_[0]).mean(axis=1)
            for f_name, imp in zip(FEATURE_COLUMNS, mlp_layer0):
                feat_importances[f_name] = round(float(imp), 4)

        results[name] = {
            'precision': round(prec, 4),
            'recall': round(rec, 4),
            'f1_score': round(f1, 4),
            'roc_auc': round(auc, 4),
            'confusion_matrix': {'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn},
            'fpr': round(fpr, 4),
            'fnr': round(fnr, 4),
            'train_time_sec': round(train_duration, 3),
            'inference_latency_us': round(mean_lat_us, 2),
            'inference_latency_std_us': round(std_lat_us, 2),
            'feature_importances': feat_importances
        }

        print(f"=== {name} ===")
        print(f" Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f} | ROC-AUC: {auc:.4f}")
        print(f" Confusión: TP={tp}, TN={tn}, FP={fp}, FN={fn} (FPR={fpr:.2%}, FNR={fnr:.2%})")
        print(f" Latencia : {mean_lat_us:.1f} ± {std_lat_us:.1f} µs/flujo | Entrenamiento: {train_duration:.2f}s")

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model_obj = model

    print("\n" + "=" * 70)
    print(f"[*] MODELO SELECCIONADO: {best_model_name} (F1-Score: {best_f1:.4f})")
    print("=" * 70)

    # 3. Guardar modelo serializado (.pkl)
    best_model_path = MODEL_OUTPUT_DIR / "firenet_best_model.pkl"
    # Serialización en pickle estándar (protocolo 4) para compatibilidad universal con joblib.load,
    # pickle.load y extensiones de visualización (VS Code PyData Viewer / Netron)
    with open(best_model_path, "wb") as f:
        pickle.dump(best_model_obj, f, protocol=4)
    print(f"[+] Artefacto serializado guardado en: {best_model_path}")

    # 4. Guardar metadatos del modelo
    metadata = {
        'best_model': best_model_name,
        'features': FEATURE_COLUMNS,
        'training_timestamp': int(time.time()),
        'dataset_path': str(dataset_path),
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'comparison': results,
        'best_metrics': results[best_model_name]
    }

    metadata_path = MODEL_OUTPUT_DIR / "model_metadata.json"
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Metadatos del modelo guardados en: {metadata_path}")

    # 5. Guardar registro experimental en experiments/runs/
    exp_log_path = EXPERIMENTS_DIR / f"RUN_TRAIN_EVAL_{int(time.time())}.json"
    with open(exp_log_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Registro de corrida experimental guardado en: {exp_log_path}")

    return best_model_name, best_model_obj, results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="FireNet-AI Model Training & Comparative Evaluation")
    parser.add_argument("--dataset", "-d", default=str(DEFAULT_DATASET),
                        help=f"Ruta del archivo CSV procesado (default: {DEFAULT_DATASET})")
    args = parser.parse_args()

    train_and_evaluate(args.dataset)
