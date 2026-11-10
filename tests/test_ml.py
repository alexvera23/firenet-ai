"""
FireNet-AI - Pruebas Unitarias de Fase 2 (Dataset y ML)
Verifica la integridad del dataset procesado, la conformidad del esquema,
la carga del modelo serializado y la consistencia de las inferencias.
"""

import json
from pathlib import Path
import pytest
import pandas as pd
import numpy as np
import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "dataset_v1.csv"
SCHEMA_PATH = PROJECT_ROOT / "data" / "schemas" / "dataset_schema.json"
MODEL_PATH = PROJECT_ROOT / "models" / "firenet_best_model.pkl"
METADATA_PATH = PROJECT_ROOT / "models" / "model_metadata.json"

REQUIRED_COLUMNS = [
    "flow_id", "run_id", "scenario_id",
    "ip_version", "protocol", "duration",
    "packets", "bytes", "pps", "bps",
    "pkts_fwd", "pkts_rev", "ratio_pkts",
    "mean_pkt_size", "src_port", "dst_port",
    "syn_flag", "label"
]

FEATURE_COLUMNS = [
    'ip_version', 'protocol', 'duration', 'packets', 'bytes',
    'pps', 'bps', 'pkts_fwd', 'pkts_rev', 'ratio_pkts',
    'mean_pkt_size', 'src_port', 'dst_port', 'syn_flag'
]


def test_dataset_exists_and_not_empty():
    """El dataset procesado debe existir y contener al menos 1000 registros."""
    assert DATASET_PATH.exists(), f"Dataset no encontrado en {DATASET_PATH}"
    df = pd.read_csv(DATASET_PATH)
    assert len(df) >= 1000, f"El dataset contiene sólo {len(df)} registros"


def test_dataset_schema_conformity():
    """El dataset debe tener todas las columnas requeridas sin valores nulos."""
    df = pd.read_csv(DATASET_PATH)
    for col in REQUIRED_COLUMNS:
        assert col in df.columns, f"Falta la columna '{col}' en el dataset"
    assert df.isnull().sum().sum() == 0, "Existen valores nulos en el dataset"


def test_dataset_scenario_and_label_distribution():
    """El dataset debe incluir todos los escenarios E0-E5 y ambas etiquetas (0 y 1)."""
    df = pd.read_csv(DATASET_PATH)
    expected_scenarios = {"E0", "E1", "E2", "E3", "E4", "E5"}
    present_scenarios = set(df["scenario_id"].unique())
    assert expected_scenarios.issubset(present_scenarios), f"Faltan escenarios: {expected_scenarios - present_scenarios}"

    labels = set(df["label"].unique())
    assert labels == {0, 1}, f"Etiquetas inválidas o incompletas: {labels}"


def test_model_artifact_loadable():
    """El artefacto serializado del mejor modelo debe existir y poder cargarse."""
    assert MODEL_PATH.exists(), f"Modelo no encontrado en {MODEL_PATH}"
    model = joblib.load(MODEL_PATH)
    assert hasattr(model, "predict"), "El modelo cargado no implementa el método predict"
    assert hasattr(model, "predict_proba"), "El modelo cargado no implementa predict_proba"


def test_model_inference():
    """El modelo debe generar predicciones coherentes en un vector de características sintético."""
    model = joblib.load(MODEL_PATH)
    
    # Vector de prueba de 14 características
    dummy_input = pd.DataFrame([{
        'ip_version': 4,
        'protocol': 6,
        'duration': 1.5,
        'packets': 10,
        'bytes': 1500,
        'pps': 6.67,
        'bps': 8000.0,
        'pkts_fwd': 6,
        'pkts_rev': 4,
        'ratio_pkts': 1.5,
        'mean_pkt_size': 150.0,
        'src_port': 45678,
        'dst_port': 80,
        'syn_flag': 1
    }])
    
    preds = model.predict(dummy_input)
    assert preds[0] in [0, 1], f"Predicción fuera de rango binario: {preds[0]}"

    probs = model.predict_proba(dummy_input)
    assert probs.shape == (1, 2), f"Forma de probabilidades incorrecta: {probs.shape}"
    assert 0.0 <= probs[0][1] <= 1.0, "Probabilidad de ataque fuera del rango [0, 1]"


def test_model_metadata_validity():
    """El archivo de metadatos del modelo debe existir y contener métricas clave."""
    assert METADATA_PATH.exists(), f"Metadatos no encontrados en {METADATA_PATH}"
    with open(METADATA_PATH, "r") as f:
        meta = json.load(f)
    assert "best_model" in meta
    assert "best_metrics" in meta
    assert meta["best_metrics"]["f1_score"] > 0.8
