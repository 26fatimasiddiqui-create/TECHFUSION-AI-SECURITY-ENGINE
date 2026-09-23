# PS-8 Security Monitoring Platform PowerShell Launcher

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   Starting PS-8 Security Platform (PowerShell)                 " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Python is not found in your system PATH." -ForegroundColor Red
    Write-Host "Please install Python 3.10+ and add it to your PATH." -ForegroundColor Yellow
    exit 1
}

python run.py
