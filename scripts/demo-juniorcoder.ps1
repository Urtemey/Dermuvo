param(
    [string]$InputAssembly
)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($InputAssembly)) {
    $InputAssembly = Join-Path $projectRoot 'artifacts/juniorcoder-coverage-20260917/input/CodeAnalyzer.dll'
}
$InputAssembly = (Resolve-Path -LiteralPath $InputAssembly).Path
$output = Join-Path $projectRoot ('artifacts/demo-juniorcoder-' + [Guid]::NewGuid().ToString('N'))
Push-Location $projectRoot
try {
    dotnet build Durevo.slnx -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Durevo build failed.' }
    dotnet run --project tests/Durevo.Tests -c Release --no-build -- --probe-juniorcoder-analyzer $InputAssembly $output
    if ($LASTEXITCODE -ne 0) { throw 'CodeAnalyzer comparison failed; inspect the retained demo output.' }
    Write-Output "Demo output: $output"
    Write-Output 'Scope: cached real game DLL, basic obfuscation and differential execution. Not a complete protected game.'
    Write-Output 'The source DLL and JuniorCoder installation are not replaced.'
}
finally { Pop-Location }
