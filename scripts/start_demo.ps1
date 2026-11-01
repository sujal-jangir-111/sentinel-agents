<#
.SYNOPSIS
  Start (or stop) the Sentinel live demo on Windows: the demo target app on :9000 plus the 5 agents,
  each in its own PowerShell window.

.EXAMPLE
  .\scripts\start_demo.ps1                 # demo app + 5 agents (payment required)
  .\scripts\start_demo.ps1 -Web            # web console, one supervised window: demo app + 5 agents (local, no payment) + http://127.0.0.1:8080
  .\scripts\start_demo.ps1 -SkipPayment    # dev only: skip the 0.1 FET payment (approval in chat still required)
  .\scripts\start_demo.ps1 -NoDemoApp      # agents only (target is deployed elsewhere)
  .\scripts\start_demo.ps1 -Stop           # close everything this script started

  If scripts are blocked:  powershell -ExecutionPolicy Bypass -File .\scripts\start_demo.ps1
#>
param(
    [switch]$SkipPayment,
    [switch]$NoDemoApp,
    [switch]$Stop,
    [switch]$Local,
    [switch]$Web,
    [int]$StaggerSeconds = 3
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$pidFile = Join-Path $root ".demo_pids"

if ($Stop) {
    if (-not (Test-Path $pidFile)) { Write-Host "Nothing to stop (no .demo_pids file)."; exit 0 }
    foreach ($line in Get-Content $pidFile) {
        $parts = $line -split "\|"
        if ($parts.Count -lt 2) { continue }
        # A window closed by hand must not stop the rest, and Windows may have reused its PID for something else
        $window = Get-Process -Id $parts[0] -ErrorAction SilentlyContinue
        if (-not $window -or $window.ProcessName -ne "powershell") { Write-Host "$($parts[1]) was already closed"; continue }
        # /T also closes the python process running inside that window; only PIDs this script recorded are touched
        & taskkill.exe /PID $parts[0] /T /F | Out-Null
        Write-Host "Stopped $($parts[1]) (pid $($parts[0]))"
    }
    Remove-Item $pidFile -Force
    exit 0
}

$py = Join-Path $root "venv\Scripts\python.exe"
if (-not (Test-Path $py)) { Write-Error "venv not found. Run: python -m venv venv ; .\venv\Scripts\pip install -r requirements.txt" }
if (-not (Test-Path (Join-Path $root ".env"))) { Write-Error ".env not found. Copy .env.example to .env and fill it in." }
if (Test-Path $pidFile) { Write-Error "Already started (.demo_pids exists). Run .\scripts\start_demo.ps1 -Stop first." }

# Read a few values from .env (never printed)
$envMap = @{}
foreach ($line in Get-Content (Join-Path $root ".env")) {
    if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$' -and -not $line.TrimStart().StartsWith("#")) { $envMap[$Matches[1]] = $Matches[2].Trim('"').Trim("'") }
}
function Need($name) { if (-not $envMap[$name]) { Write-Warning "$name is empty in .env" ; return $false } ; return $true }
$ok = $true
foreach ($n in @("ORCHESTRATOR_SEED","WATCHDOG_SEED","DETECTIVE_SEED","SCANNER_SEED","EXECUTOR_SEED","GITHUB_TOKEN","DEMO_ADMIN_TOKEN","DEMO_REPO_FULL_NAME")) { if (-not (Need $n)) { $ok = $false } }
if (-not $envMap["GEMINI_API_KEY"] -and -not $envMap["ASI1_API_KEY"] -and -not $envMap["GROQ_API_KEY"] -and -not $env:GROQ_API_KEY) { Write-Warning "Set GROQ_API_KEY (or GEMINI_API_KEY / ASI1_API_KEY) in .env for the LLM"; $ok = $false }
if ($envMap["DEMO_REPO_FULL_NAME"] -like "your-org/*") { Write-Warning "DEMO_REPO_FULL_NAME is still the placeholder"; $ok = $false }
if ($Web) { $Local = $true; $SkipPayment = $true }   # the web console talks to Agent_1 over local HTTP and has no payment step
$payment = (-not $SkipPayment) -and ($envMap["SKIP_PAYMENT"] -ne "true")
if ($payment -and (-not $envMap["ORCHESTRATOR_WALLET_ADDRESS"] -or $envMap["ORCHESTRATOR_WALLET_ADDRESS"] -like "fetch1...*")) {
    Write-Warning "ORCHESTRATOR_WALLET_ADDRESS is not set; the payment step will fail. Set it, or use -SkipPayment for a dry run."
    $ok = $false
}
if (-not $ok) { Write-Error "Fix the .env values above and run again." }

# Child windows inherit these
$env:DEMO_ADMIN_TOKEN = $envMap["DEMO_ADMIN_TOKEN"]
$env:PYTHONUTF8 = "1"
if ($SkipPayment) { $env:SKIP_PAYMENT = "true" }
if ($Local) { $env:AGENT_MAILBOX = "false" }   # no Agentverse: agents talk over local HTTP ports 8001-8005

$started = @()
function Launch($title, $command) {
    $full = "`$host.UI.RawUI.WindowTitle = '$title'; $command"
    $p = Start-Process powershell.exe -ArgumentList @("-NoExit", "-NoProfile", "-Command", $full) -WorkingDirectory $root -PassThru
    $script:started += "$($p.Id)|$title"
    Set-Content -Path $pidFile -Value $script:started
    Write-Host "Started $title (pid $($p.Id))"
}

if ($Web) {
    # One supervised window instead of seven: a stopped agent comes back by itself (scripts/run_stack.py)
    $dist = Join-Path $root "frontend\dist\index.html"
    if (-not (Test-Path $dist)) {
        Write-Host "Building the web console (first run)..."
        Push-Location (Join-Path $root "frontend")
        if (-not (Test-Path "node_modules")) { & npm install --no-fund --no-audit | Out-Null }
        & npm run build | Out-Null
        Pop-Location
    }
    Launch "Sentinel :8080" "& '$py' -m scripts.run_stack"
    Write-Host "Waiting for the agents..."
    $online = $false
    for ($i = 0; $i -lt 60 -and -not $online; $i++) {
        Start-Sleep -Seconds 1
        try { $online = (Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/health" -TimeoutSec 2).agents_online } catch { }
    }
    if ($online) { Write-Host "All agents online. Web console: http://127.0.0.1:8080" }
    else { Write-Warning "The agents did not come online within 60 seconds. Check the 'Sentinel :8080' window." }
    Write-Host "Stop everything with:  .\scripts\start_demo.ps1 -Stop"
    exit 0
}

if (-not $NoDemoApp) {
    Launch "Sentinel: demo target :9000" "& '$py' -m uvicorn demo_target_app.app:app --host 127.0.0.1 --port 9000"
    for ($i = 0; $i -lt 20; $i++) {
        try { $r = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:9000/health" -TimeoutSec 2; if ($r.StatusCode -eq 200) { break } } catch { Start-Sleep -Milliseconds 500 }
    }
    try { Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:9000/api/checkout" -TimeoutSec 5 | Out-Null; Write-Warning "/api/checkout returned 200: the demo app is already PATCHED. POST /admin/simulate-fault to re-break it." }
    catch { Write-Host "Demo target is up and /api/checkout is failing as intended (HTTP 500)." }
}

# Receivers first, the Orchestrator last so it can reach everyone when the first chat arrives
$agents = @(
    @("Agent_5 (Remediation-Executor) :8005", "agents.Agent_5"),
    @("Agent_4 (Vuln-CVE-Scanner) :8004", "agents.Agent_4"),
    @("Agent_3 (Commit-Detective) :8003", "agents.Agent_3"),
    @("Agent_2 (Telemetry-Watchdog) :8002", "agents.Agent_2"),
    @("Agent_1 (Sentinel-Orchestrator) :8001", "agents.Agent_1")
)
foreach ($a in $agents) { Launch $a[0] "& '$py' -m $($a[1])"; Start-Sleep -Seconds $StaggerSeconds }

Write-Host ""
Write-Host "All windows started. Payment: $(if ($payment) { 'REQUIRED (0.1 FET on Dorado)' } else { 'SKIPPED (dev mode)' })"
Write-Host ""
if ($Local) {
    Write-Host "LOCAL mode (AGENT_MAILBOX=false): no mailboxes needed; agents reach each other on 127.0.0.1:8001-8005."
    Write-Host "Stop everything with:  .\scripts\start_demo.ps1 -Stop"
    exit 0
}
Write-Host "NEXT: connect all 5 agents' mailboxes in the Agentverse Inspector."
Write-Host "Stop everything with:  .\scripts\start_demo.ps1 -Stop"
