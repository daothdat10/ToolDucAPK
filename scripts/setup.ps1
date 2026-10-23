param([string]$CacheDirectory = "", [switch]$Force)
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONNOUSERSITE = "1"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$workspaceRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $workspaceRoot
if ($env:OS -ne "Windows_NT" -or -not [Environment]::Is64BitOperatingSystem) {
    throw "DucAPK portable runtime requires Windows x64."
}
$manifest = Get-Content -LiteralPath (Join-Path $workspaceRoot "runtime-manifest.json") -Raw | ConvertFrom-Json
if (-not $CacheDirectory) { $CacheDirectory = Join-Path $workspaceRoot "tools\runtime-cache" }
New-Item -ItemType Directory -Path $CacheDirectory -Force | Out-Null
$cacheRoot = (Resolve-Path -LiteralPath $CacheDirectory).Path
foreach ($asset in $manifest.assets) {
    $missing = @($asset.required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $workspaceRoot $_)) })
    $stampFile = Join-Path $workspaceRoot ("tools\.installed-" + $asset.name + ".sha256")
    $installedHash = if (Test-Path -LiteralPath $stampFile) { (Get-Content -LiteralPath $stampFile -Raw).Trim() } else { "" }
    if (-not $Force -and $missing.Count -eq 0 -and $installedHash -eq $asset.sha256) {
        Write-Host "Already installed: $($asset.name)"
        continue
    }
    $archivePath = Join-Path $cacheRoot $asset.name
    if (Test-Path -LiteralPath $archivePath) {
        $actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $asset.sha256) {
            throw "Checksum mismatch in cached $($asset.name). Remove that archive from $cacheRoot and retry."
        }
    } else {
        $partialPath = $archivePath + ".download"
        Write-Host "Downloading $($asset.name) ($([math]::Round($asset.size / 1MB)) MB)..."
        # A failed transfer leaves only .download; a retry starts a fresh transfer.
        $oldProgress = $ProgressPreference
        $ProgressPreference = "SilentlyContinue"
        try { Invoke-WebRequest -Uri $asset.url -OutFile $partialPath -UseBasicParsing }
        finally { $ProgressPreference = $oldProgress }
        $actual = (Get-FileHash -LiteralPath $partialPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $asset.sha256) { throw "Checksum mismatch for downloaded $($asset.name)." }
        Move-Item -LiteralPath $partialPath -Destination $archivePath -Force
    }
    $destination = Join-Path $workspaceRoot $asset.unpack_to
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    Write-Host "Extracting $($asset.name)..."
    Expand-Archive -LiteralPath $archivePath -DestinationPath $destination -Force
    foreach ($required in $asset.required) {
        if (-not (Test-Path -LiteralPath (Join-Path $workspaceRoot $required))) { throw "Missing file after extraction: $required" }
    }
    Set-Content -LiteralPath $stampFile -Value $asset.sha256 -Encoding ASCII
}
$python = Join-Path $workspaceRoot "tools\python\python.exe"
$venvPython = Join-Path $workspaceRoot ".venv\Scripts\python.exe"
& $python -m venv (Join-Path $workspaceRoot ".venv")
if ($LASTEXITCODE -ne 0) { throw "Could not create Python virtual environment." }
& $venvPython -m pip install --no-index --find-links (Join-Path $workspaceRoot "tools\wheels") -r (Join-Path $workspaceRoot "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "Could not install Python dependencies." }
& $venvPython -m ducapk.toolchain
if ($LASTEXITCODE -ne 0) { throw "Runtime validation failed." }
& $venvPython -c "import tkinter, tkinterdnd2, UnityPy; from Crypto.Cipher import AES; from ducapk.runner import analyze; print('Python dependencies OK')"
if ($LASTEXITCODE -ne 0) { throw "Python dependency validation failed." }
