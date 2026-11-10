#!/usr/bin/env python3
"""
FireNet-AI - Script de Evaluación y Diagnóstico Detallado de Modelos ML (Fase 2)
Permite inspeccionar el modelo entrenado (models/firenet_best_model.pkl),
desglosar la tasa de detección por escenario individual (E0 a E5),
analizar el impacto de los umbrales de decisión (0.50 a 0.95) y mostrar la importancia de variables.
"""

import os
import sys
import json
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

from src.ml.train import FEATURE_COLUMNS, DEFAULT_DATASET, MODEL_OUTPUT_DIR


def evaluate_detailed(model_path=None, dataset_path=None):
    if model_path is None:
        model_path = MODEL_OUTPUT_DIR / "firenet_best_model.pkl"
    if dataset_path is None:
        dataset_path = DEFAULT_DATASET

    model = joblib.load(model_path)
    df = pd.read_csv(dataset_path)

    print("=" * 70)
    print(" FIRENET-AI: EVALUACIÓN DETALLADA POR ESCENARIO Y UMBRAL")
    print("=" * 70)
    print(f" [*] Modelo cargado : {model_path}")
    print(f" [*] Dataset        : {dataset_path} ({len(df)} registros)")

    X = df[FEATURE_COLUMNS]
    y = df['label']

    # Probabilidades y predicciones base
    if hasattr(model, "predict_proba"):
        scores = model.predict_proba(X)[:, 1]
    else:
        scores = model.predict(X)

    # 1. Desglose por Escenario Individual
    print("\n=== 1. TASA DE DETECCIÓN Y CLASIFICACIÓN POR ESCENARIO ===")
    scenarios = sorted(df['scenario_id'].unique())
    scenario_metrics = []

    for sc in scenarios:
        sc_mask = (df['scenario_id'] == sc)
        sc_y = y[sc_mask]
        sc_scores = scores[sc_mask]
        sc_preds = (sc_scores >= 0.5).astype(int)

        total_sc = len(sc_y)
        correct = int((sc_preds == sc_y).sum())
        acc = correct / max(total_sc, 1)

        if sc == "E0":
            # Para E0 (Benigno), lo crítico es el FPR (falsos positivos)
            fp_count = int((sc_preds == 1).sum())
            fp_rate = fp_count / max(total_sc, 1)
            print(f" [{sc} - Benigno] Total: {total_sc:4d} | Correctos: {correct:4d} | Falsos Positivos: {fp_count:3d} (FPR: {fp_rate:.2%})")
            scenario_metrics.append({'scenario': sc, 'type': 'benign', 'total': total_sc, 'fp': fp_count, 'fpr': fp_rate})
        else:
            # Para ataques (E1..E5), lo crítico es la Tasa de Detección (Recall)
            attack_mask = (sc_y == 1)
            detected = int((sc_preds[attack_mask] == 1).sum())
            total_attacks = int(attack_mask.sum())
            recall = detected / max(total_attacks, 1)
            print(f" [{sc} - Ataque ] Total Flujos: {total_sc:4d} | Ataques Detectados: {detected:4d}/{total_attacks:4d} (Recall: {recall:.2%})")
            scenario_metrics.append({'scenario': sc, 'type': 'attack', 'total': total_sc, 'detected': detected, 'recall': recall})

    # 2. Análisis de Umbral de Decisión (Threshold Sweep)
    print("\n=== 2. CALIBRACIÓN DE UMBRALES DE DECISIÓN (SCORE T) ===")
    print(" Umbral (T) | Precision | Recall  | F1-Score | FPR (Falsos Bloqueos) | FNR (Ataques Evasivos)")
    print("-" * 75)

    thresholds = [0.50, 0.65, 0.75, 0.85, 0.90, 0.95]
    for t in thresholds:
        t_preds = (scores >= t).astype(int)
        cm = confusion_matrix(y, t_preds)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = [int(v) for v in cm.ravel()]
            prec = tp / max(tp + fp, 1)
            rec = tp / max(tp + fn, 1)
            f1 = (2 * prec * rec) / max(prec + rec, 1e-6)
            fpr = fp / max(fp + tn, 1)
            fnr = fn / max(fn + tp, 1)
            print(f"   {t:.2f}     |  {prec:.4f}   | {rec:.4f}  |  {f1:.4f}  |        {fpr:.2%}        |        {fnr:.2%}")

    # 3. Importancia de Características (Feature Importance)
    print("\n=== 3. IMPORTANCIA DE VARIABLES (EXPLICABILIDAD) ===")
    if hasattr(model, "feature_importances_"):
        imps = model.feature_importances_
        sorted_indices = np.argsort(imps)[::-1]
        for rank, idx in enumerate(sorted_indices, 1):
            print(f"   {rank:2d}. {FEATURE_COLUMNS[idx]:15s}: {imps[idx]:.4f} ({imps[idx]*100:.1f}%)")
    elif hasattr(model, "named_steps") and hasattr(model.named_steps.get('classifier'), "coefs_"):
        coefs = np.abs(model.named_steps['classifier'].coefs_[0]).mean(axis=1)
        sorted_indices = np.argsort(coefs)[::-1]
        for rank, idx in enumerate(sorted_indices, 1):
            print(f"   {rank:2d}. {FEATURE_COLUMNS[idx]:15s}: {coefs[idx]:.4f}")

    print("=" * 70)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="FireNet-AI Model Evaluation & Diagnostic")
    parser.add_argument("--model", "-m", default=None, help="Ruta al modelo serializado (.pkl)")
    parser.add_argument("--dataset", "-d", default=None, help="Ruta al archivo CSV de flujos")
    args = parser.parse_args()

    evaluate_detailed(args.model, args.dataset)
