@echo off
echo.
echo  ================================
echo   SENTINEL - Starting Services
echo  ================================
echo.

:: Check Docker is running
docker info > nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Docker is not running!
    echo  Please start Docker Desktop first.
    pause
    exit /b
)

echo  [1/3] Building containers...
docker-compose build

echo.
echo  [2/3] Starting all services...
docker-compose up -d

echo.
echo  [3/3] Opening dashboard...
timeout /t 3 /nobreak > nul
start http://localhost:3000

echo.
echo  ================================
echo   All services running!
echo.
echo   Dashboard     : http://localhost:3000
echo   DDoS Scanner  : http://localhost:8000/docs
echo   URL Scanner   : http://localhost:8001/docs
echo  ================================
echo.
echo  To stop everything run: stop.bat
echo.
pause