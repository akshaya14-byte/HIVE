@echo off
echo.
echo  ================================
echo   SENTINEL - Stopping Services
echo  ================================
echo.

docker-compose down

echo.
echo  All services stopped.
echo.
pause