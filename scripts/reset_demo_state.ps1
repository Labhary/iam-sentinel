param(
    [string]$PythonPath = ".\.venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$dataDir = Join-Path $projectRoot "data"
$dbFiles = @(
    (Join-Path $dataDir "findings.db"),
    (Join-Path $dataDir "findings.db-wal"),
    (Join-Path $dataDir "findings.db-shm")
)

foreach ($dbFile in $dbFiles) {
    $fullPath = [System.IO.Path]::GetFullPath($dbFile)
    $expectedPrefix = [System.IO.Path]::GetFullPath($dataDir)
    if (-not $fullPath.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove path outside data directory: $fullPath"
    }
    if (Test-Path -LiteralPath $fullPath) {
        Remove-Item -LiteralPath $fullPath -Force
        Write-Host "Removed $fullPath"
    }
}

& $PythonPath -c "from core.analysis_runner import run_analysis; result = run_analysis(); print('Seeded {} findings at {}'.format(result['total_findings'], result['execution_timestamp']))"
