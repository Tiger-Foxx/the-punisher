@echo off
echo.
echo ============================================================
echo            THE PUNISHER - NetworkController
echo                  Admin Mode Launcher
echo ============================================================
echo.

REM Vérifier si on est déjà admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Privilèges administrateur détectés
    echo 🚀 Lancement de l'application...
    echo.
    python -m app.main
    pause
) else (
    echo ⚠️  Privilèges administrateur requis
    echo 🔄 Relancement en mode administrateur...
    echo.
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %cd% && python -m app.main && pause' -Verb RunAs"
)