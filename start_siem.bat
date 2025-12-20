@echo off
setlocal

echo [1/3] Starting NetWatch-SIEM Backend...
start "NetWatch Backend" cmd /k "cd backend && python -m pip install -r requirements.txt && python -m uvicorn main:app --reload --port 8000"

echo [2/3] Starting NetWatch-SIEM Frontend...
:: Clearing cache to avoid build issues
start "NetWatch Frontend" cmd /k "cd frontend && if exist node_modules (echo Updating packages...) else (echo Installing packages...) && npm install && npm run dev"

echo [3/3] Launching Command Center...
echo Waiting for servers to initialize...
timeout /t 8 >nul
start http://localhost:5173
start http://localhost:8000/docs

echo.
echo NetWatch-SIEM is running.
echo If the browser didn't open automatically, use these links:
echo Dashboard: http://localhost:5173
echo API Docs:  http://localhost:8000/docs
echo.
pause
