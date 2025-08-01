# Script PowerShell pour lancer en mode admin
Write-Host "============================================================" -ForegroundColor Red
Write-Host "            THE PUNISHER - NetworkController" -ForegroundColor Red  
Write-Host "                  Admin Mode Launcher" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""

# Vérifier si on est déjà admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if ($isAdmin) {
    Write-Host "✅ Privilèges administrateur détectés" -ForegroundColor Green
    Write-Host "🚀 Lancement de l'application..." -ForegroundColor Cyan
    Write-Host ""
    
    python -m app.main
    
    Write-Host ""
    Write-Host "Appuyez sur une touche pour quitter..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
} else {
    Write-Host "⚠️  Privilèges administrateur requis" -ForegroundColor Yellow
    Write-Host "🔄 Relancement en mode administrateur..." -ForegroundColor Cyan
    Write-Host ""
    
    # Relancer en admin
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
}