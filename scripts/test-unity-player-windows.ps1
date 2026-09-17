param([string]$PlayerPath = '', [string]$GameAssembly = '', [string]$LicenseAssembly = '')
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (!$PlayerPath) { $PlayerPath = Join-Path $projectRoot 'artifacts/unity-player-win/DurevoPlayerSmoke.exe' }
$PlayerPath = (Resolve-Path -LiteralPath $PlayerPath).Path
Push-Location $projectRoot
try {
    $fixtures = Join-Path $projectRoot ('artifacts/player-fixtures-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $fixtures | Out-Null
    $vector = Get-Content tests/Durevo.Tests/Fixtures/windows-license-vector.json -Raw | ConvertFrom-Json
    [IO.File]::WriteAllBytes((Join-Path $fixtures 'ticket.bin'), [Convert]::FromBase64String($vector.Ticket))
    [IO.File]::WriteAllBytes((Join-Path $fixtures 'public.bin'), [Convert]::FromBase64String($vector.PublicKey))
    $fixtureArgs = @('--write-mono-fixtures',$fixtures)
    if ($GameAssembly) { $fixtureArgs += @('--game-strings',(Resolve-Path -LiteralPath $GameAssembly).Path) }
    dotnet run --project tests/Durevo.Tests -c Release --no-build -- @fixtureArgs
    if ($LASTEXITCODE -ne 0) { throw 'Fixture generation failed.' }
    dotnet run --project tests/Durevo.Tests -c Release --no-build -- --write-verified-native-fixtures $fixtures artifacts/native-win-x64/durevo_vm.dll
    if ($LASTEXITCODE -ne 0) { throw 'Verified native fixture generation failed.' }
    if ($LicenseAssembly) {
        dotnet run --project tests/Durevo.Tests -c Release --no-build -- --write-cipher-fixtures $fixtures (Resolve-Path -LiteralPath $LicenseAssembly).Path
        if ($LASTEXITCODE -ne 0) { throw 'Cipher fixture generation failed.' }
    }
    $log = Join-Path $fixtures 'player.log'
    $process = Start-Process -FilePath $PlayerPath -ArgumentList @('-batchmode','-nographics','-logFile',('"' + $log + '"'),'--durevo-fixtures',('"' + $fixtures + '"')) -WindowStyle Hidden -PassThru
    if (!$process.WaitForExit(120000)) { $process.Kill(); throw "Player test timed out: $log" }
    $text = [IO.File]::ReadAllText($log)
    $text -split '[\r\n]+' | Where-Object { $_ -match 'DUREVO_|PASS:|KNOWN GAP:|BINDING ' }
    if ($process.ExitCode -ne 0 -or $text -notmatch 'DUREVO_PLAYER_RESULT exitCode=0' -or $text -notmatch 'PASS: native signed key grant enables encrypted VM' -or $text -notmatch 'pointerSize=8') {
        throw "Player test failed: exit=$($process.ExitCode), log=$log"
    }
    if ($text -notmatch 'PASS: verified native snapshot binding') { throw "Verified native smoke did not run: $log" }
    if ($text -notmatch 'PASS: protected nested handlers, filters and finally' -or
        ($LicenseAssembly -and $text -notmatch 'PASS: actual license cipher protected')) {
        throw "Exception/cipher smoke did not run: $log"
    }
    if ($GameAssembly -and ($text -notmatch 'PASS: native actual cooperative string VM' -or $text -notmatch 'PASS: managed actual cooperative string VM')) {
        throw "Actual game string VM smoke did not run: $log"
    }
    Write-Output "Player evidence: $log"
}
finally { Pop-Location }
