$ErrorActionPreference = "Stop"

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Get-Command python -ErrorAction SilentlyContinue
$bundledPython = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"

if ($python) {
    & $python.Source (Join-Path $projectDir "generate_certs.py") @args
} elseif (Test-Path $bundledPython) {
    & $bundledPython (Join-Path $projectDir "generate_certs.py") @args
} else {
    throw "Python nao encontrado. Instale Python 3.10+ ou execute com um interpretador Python disponivel."
}
