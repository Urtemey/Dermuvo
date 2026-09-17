param([Parameter(Mandatory=$true)][string]$Source)
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Source=(Resolve-Path -LiteralPath $Source).Path
$pilot=Join-Path $root ('artifacts/player-pilot-'+[Guid]::NewGuid().ToString('N'))
$entries=Get-ChildItem -LiteralPath $Source -Recurse -Force
if ($entries | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }) { throw 'Source links require explicit review.' }
$files=@($entries | Where-Object { -not $_.PSIsContainer -and -not ($_.DirectoryName -eq $Source -and $_.Name -like "unins*") })
New-Item -ItemType Directory -Path $pilot | Out-Null
$inventory=@($files | ForEach-Object { [pscustomobject]@{Path=[IO.Path]::GetRelativePath($Source,$_.FullName);Length=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash} })
$inventory | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $pilot 'source-inventory.json') -Encoding utf8
foreach($variant in @('baseline','protected')) {
    $destination=Join-Path $pilot $variant
    New-Item -ItemType Directory -Path $destination | Out-Null
    Get-ChildItem -LiteralPath $Source -Force | Where-Object { $_.Name -notlike "unins*" } | Copy-Item -Destination $destination -Recurse
    foreach($entry in $inventory) {
        if((Get-FileHash -LiteralPath (Join-Path $destination $entry.Path) -Algorithm SHA256).Hash -ne $entry.Sha256) { throw 'Copy verification failed.' }
    }
}
$fixture=Get-Content (Join-Path $root 'artifacts/juniorcoder-verified-release-win-20260917/execution.json') -Raw | ConvertFrom-Json
$modules=@($fixture.Plan.Modules | Where-Object { $_.Path -match '(CodeAnalyzer|JuniorCoder.GameScene)\.dll$' })
foreach($module in $modules) {
    $name=[IO.Path]::GetFileName($module.Path)
    $relative=Join-Path 'JuniorCoder_Data/Managed' $name
    $inputDll=Join-Path $Source $relative
        $expected=@($inventory | Where-Object { $_.Path.Replace('\','/') -eq $relative.Replace('\','/') })
    if($expected.Count -ne 1 -or (Get-FileHash -LiteralPath $inputDll -Algorithm SHA256).Hash -ne $expected[0].Sha256) { throw "Source changed after copying: $name" }
    $analysis=(& dotnet (Join-Path $root 'src/Durevo.Cli/bin/Release/net10.0/Durevo.Cli.dll') analyze $inputDll | Out-String) | ConvertFrom-Json
    if($LASTEXITCODE -ne 0 -or $analysis.AssemblyBlockers.Count -ne 0) { throw "Unsupported assembly: $name" }
    foreach($signature in $module.Methods) {
        $match=@($analysis.Methods | Where-Object { $_.Signature -ceq $signature -and $_.ObfuscationEligible })
        if($match.Count -ne 1) { throw "Selected method not compatible: $signature" }
    }
    $methods=Join-Path $pilot ($name+'.methods.txt')
    [IO.File]::WriteAllLines($methods,[string[]]$module.Methods,[Text.UTF8Encoding]::new($false))
    $transformed=Join-Path $pilot ($name+'.transform')
    & dotnet (Join-Path $root 'src/Durevo.Cli/bin/Release/net10.0/Durevo.Cli.dll') protect $inputDll $transformed $methods
    if($LASTEXITCODE -ne 0) { throw 'Protection failed.' }
    Copy-Item -LiteralPath (Join-Path $transformed $name) -Destination (Join-Path (Join-Path $pilot 'protected') $relative)
}
$changes=@()
foreach($entry in $inventory) {
    if((Get-FileHash -LiteralPath (Join-Path $Source $entry.Path) -Algorithm SHA256).Hash -ne $entry.Sha256) { throw 'Source changed during pilot preparation.' }
    $newHash=(Get-FileHash -LiteralPath (Join-Path (Join-Path $pilot 'protected') $entry.Path) -Algorithm SHA256).Hash
    if($newHash -ne $entry.Sha256) { $changes += [pscustomobject]@{Path=$entry.Path;Before=$entry.Sha256;After=$newHash} }
}
if($changes.Count -ne 2) { throw 'Unexpected changed-file count.' }
[pscustomobject]@{Source=$Source;Pilot=$pilot;Mode='basic-obfuscation';ProtectedMethods=11;Files=$files.Count;Changes=$changes;Scope='Prepared copies only. No gameplay or performance acceptance yet. Existing update manifests are unchanged and may reject modified DLLs; updater behavior must be tested separately.'} |
    ConvertTo-Json -Depth 6 | Set-Content (Join-Path $pilot 'preparation.json') -Encoding utf8
Write-Output "PILOT_ROOT=$pilot"
