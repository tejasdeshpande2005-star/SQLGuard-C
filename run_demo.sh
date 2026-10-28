#!/usr/bin/env bash
set +e
python -m sqlguard.cli analyze examples/vulnerable_example.py
printf '\n--- SAFE EXAMPLE ---\n'
python -m sqlguard.cli analyze examples/safe_example.py
printf '\n--- PARAMETERIZATION VERIFICATION ---\n'
python -m sqlguard.verification.attack_runner
