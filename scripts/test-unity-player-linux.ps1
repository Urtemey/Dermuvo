param([string]$GameAssembly = '', [string]$LicenseAssembly = '')
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$player = Join-Path $projectRoot 'artifacts/unity-player-linux'
if (!(Test-Path (Join-Path $player 'DurevoPlayerSmoke.x86_64'))) { throw 'Build the Linux player first.' }
Push-Location $projectRoot
try {
    $fixtures = Join-Path $projectRoot ('artifacts/linux-player-fixtures-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $fixtures | Out-Null
    $vector = Get-Content tests/Durevo.Tests/Fixtures/windows-license-vector.json -Raw | ConvertFrom-Json
    [IO.File]::WriteAllBytes((Join-Path $fixtures 'ticket.bin'), [Convert]::FromBase64String($vector.Ticket))
    [IO.File]::WriteAllBytes((Join-Path $fixtures 'public.bin'), [Convert]::FromBase64String($vector.PublicKey))
    $fixtureArgs = @('--write-mono-fixtures',$fixtures)
    if ($GameAssembly) { $fixtureArgs += @('--game-strings',(Resolve-Path -LiteralPath $GameAssembly).Path) }
    dotnet run --project tests/Durevo.Tests -c Release --no-build -- @fixtureArgs
    if ($LASTEXITCODE -ne 0) { throw 'Fixture generation failed.' }
    dotnet run --project tests/Durevo.Tests -c Release --no-build -- --write-verified-native-fixtures $fixtures artifacts/native-linux-x64/libdurevo_vm.so
    if ($LASTEXITCODE -ne 0) { throw 'Verified native fixture generation failed.' }
    if ($LicenseAssembly) {
        dotnet run --project tests/Durevo.Tests -c Release --no-build -- --write-cipher-fixtures $fixtures (Resolve-Path -LiteralPath $LicenseAssembly).Path
        if ($LASTEXITCODE -ne 0) { throw 'Cipher fixture generation failed.' }
    }
    $PSNativeCommandUseErrorActionPreference = $false
    $output = & docker run --rm --mount "type=bind,source=$player,target=/player-source,readonly" --mount "type=bind,source=$fixtures,target=/fixture-source,readonly" durevo-native-tests:local sh -c 'set -eu; cp -r /player-source /tmp/player; cp -r /fixture-source /tmp/fixtures; chmod +x /tmp/player/DurevoPlayerSmoke.x86_64; timeout 120 /tmp/player/DurevoPlayerSmoke.x86_64 -batchmode -nographics -logFile - --durevo-fixtures /tmp/fixtures' 2>&1
    $exitCode = $LASTEXITCODE
    $PSNativeCommandUseErrorActionPreference = $true
    $log = Join-Path $fixtures 'player.log'
    $output | Set-Content -LiteralPath $log
    $text = $output -join [Environment]::NewLine
    $output | Where-Object { "$_" -match 'DUREVO_|PASS:|KNOWN GAP:|BINDING |Exception|error while loading' }
    if ($exitCode -ne 0 -or $text -notmatch 'DUREVO_PLAYER_RESULT exitCode=0' -or $text -notmatch 'PASS: native signed key grant enables encrypted VM' -or $text -notmatch 'platform=LinuxPlayer pointerSize=8') {
        throw "Linux Player failed: exit=$exitCode; log=$log"
    }
    if ($text -notmatch 'PASS: verified native snapshot binding') { throw "Verified native smoke did not run: $log" }
    if ($text -notmatch 'PASS: protected nested handlers, filters and finally' -or
        ($LicenseAssembly -and $text -notmatch 'PASS: actual license cipher protected')) {
        throw "Exception/cipher smoke did not run: $log"
    }
    if ($GameAssembly -and ($text -notmatch 'PASS: native actual cooperative string VM' -or $text -notmatch 'PASS: managed actual cooperative string VM')) {
        throw "Actual game string VM smoke did not run: $log"
    }
    Write-Output "Linux Player evidence: $log"
}
finally { Pop-Location }
