@echo off
python -m sqlguard.cli analyze examples\vulnerable_example.py
python -m sqlguard.cli analyze examples\safe_example.py
python -m sqlguard.verification.attack_runner
pause
