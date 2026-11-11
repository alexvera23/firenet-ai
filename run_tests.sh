#!/usr/bin/env bash
# Ejecutar tests de FireNet-AI usando Python 3.14 y el site-packages del venv
# Uso: ./run_tests.sh [archivo_test] [opciones_pytest]
# Ejemplo: ./run_tests.sh tests/test_policy_firewall.py

VENV_SITE=".venv/lib/python3.12/site-packages"
TESTS=${1:-"tests/"}

PYTHONPATH=".:${VENV_SITE}" python3.14 -m pytest "${TESTS}" "${@:2}"
