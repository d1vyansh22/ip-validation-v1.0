@echo off
echo Creating virtual environment...
python -m venv ip-tool-env

echo Activating virtual environment...
call ip-tool-env\Scripts\activate

echo Installing dependencies...
pip install --upgrade pip
pip install -r requirements.txt

echo Setup complete!
echo To activate the environment later, run: ip-tool-env\Scripts\activate
pause