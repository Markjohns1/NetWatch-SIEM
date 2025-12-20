@echo off
setlocal enabledelayedexpansion

echo ===================================================
echo   NetWatch-SIEM Rapid Deployment Script
echo ===================================================

echo [1/3] Launching Backend Server...
start "NetWatch Backend" cmd /k "cd backend && set PYTHONPATH=. && echo Installing dependencies... && python -m pip install -r requirements.txt && echo Starting FastAPI... && python -m uvicorn main:app --reload --port 8000 || pause"

echo [2/3] Launching Frontend UI...
start "NetWatch Frontend" cmd /k "cd frontend && echo Checking packages... && npm install && echo Starting Vite... && npm run dev || pause"

echo [3/3] Orchestrating Browser Launch...
echo.
echo Please wait for servers to signal 'Ready'...
timeout /t 10 >nul

echo Opening Command Center...
start http://localhost:5173
start http://localhost:8000/docs

echo.
echo ---------------------------------------------------
echo   Deployment Status: Active
echo   Dashboard: http://localhost:5173
echo   API Intelligence: http://localhost:8000/docs
echo ---------------------------------------------------
echo.
echo Keep this window open or press any key to finish orchestration.
pause >nul
