@echo off
REM Setup script for Windows
python -m venv ip-tool-env
call ip-tool-env\Scripts\activate
pip install -r requirements.txt
echo Setup complete. Activate your environment with:
echo call ip-tool-env\Scripts\activate
echo Then run: python ip_lookup_enhanced.py