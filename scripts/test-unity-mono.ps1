param(
    [Parameter(Mandatory=$true)][string]$UnityEditorData
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$monoExe = Join-Path $UnityEditorData 'MonoBleedingEdge/bin/mono.exe'
$cscExe = Join-Path $UnityEditorData 'MonoBleedingEdge/lib/mono/4.5/csc.exe'
$reference = Join-Path $UnityEditorData 'NetStandard/ref/2.1.0/netstandard.dll'
foreach ($required in @($monoExe, $cscExe, $reference)) {
    if (!(Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required Unity file missing: $required" }
}
Push-Location $projectRoot
try {
    dotnet restore Durevo.slnx --locked-mode
    if ($LASTEXITCODE -ne 0) { throw 'Locked restore failed.' }
    dotnet build Durevo.slnx -c Release --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    $output = Join-Path $projectRoot ('artifacts/mono-smoke-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $output | Out-Null
    $exe = Join-Path $output 'Durevo.MonoSmoke.exe'
    & $monoExe --version
    & $monoExe $cscExe /nologo /noconfig /nostdlib /target:exe "/out:$exe" "/reference:$reference" /reference:src/Durevo.Runtime/bin/Release/netstandard2.1/Durevo.Runtime.dll tests/Durevo.MonoSmoke/Program.cs tests/Durevo.MonoSmoke/BindingProbe.cs tests/Durevo.MonoSmoke/EncryptedProbe.cs tests/Durevo.Tests/Portable/ExceptionProbe.cs tests/Durevo.Tests/Portable/VerifiedNativeProbe.cs
    if ($LASTEXITCODE -ne 0) { throw 'Smoke compilation failed.' }
    Copy-Item src/Durevo.Runtime/bin/Release/netstandard2.1/Durevo.Runtime.dll $output
    Copy-Item src/Durevo.Cli/bin/Release/net10.0/runtime-dependencies/BouncyCastle.Cryptography.dll $output
    Copy-Item src/Durevo.Cli/bin/Release/net10.0/runtime-dependencies/Mono.Cecil.dll $output
    $vector = Get-Content tests/Durevo.Tests/Fixtures/windows-license-vector.json -Raw | ConvertFrom-Json
    [IO.File]::WriteAllBytes((Join-Path $output 'ticket.bin'), [Convert]::FromBase64String($vector.Ticket))
    [IO.File]::WriteAllBytes((Join-Path $output 'public.bin'), [Convert]::FromBase64String($vector.PublicKey))
    dotnet run --project tests/Durevo.Tests -c Release --no-build -- --write-mono-fixtures $output
    if ($LASTEXITCODE -ne 0) { throw 'Fixture generation failed.' }
    & $monoExe $exe $output
    if ($LASTEXITCODE -ne 0) { throw 'Unity bundled Mono smoke failed.' }
    Write-Output "Smoke artifacts: $output"
}
finally { Pop-Location }
