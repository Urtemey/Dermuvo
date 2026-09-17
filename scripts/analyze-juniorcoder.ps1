param(
    [Parameter(Mandatory=$true)][string]$ProjectPath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$project = (Resolve-Path -LiteralPath $ProjectPath).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'Output directory must be new.' }
$cli = Join-Path $root 'src/Durevo.Cli/bin/Release/net10.0/Durevo.Cli.dll'
if (!(Test-Path -LiteralPath $cli)) { throw 'Build Durevo.Cli first.' }
$definitions = Get-ChildItem -LiteralPath (Join-Path $project 'Assets/JuniorCoder') -Filter *.asmdef -Recurse
$names = @($definitions | ForEach-Object {
    $definition = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
    if ($definition.name -notmatch '(Editor$|Tests?$|\.Debug$)' -and
        ($definition.includePlatforms -join ',') -ne 'Editor') {
        $definition.name
    }
} | Sort-Object -Unique)
New-Item -ItemType Directory -Path $output | Out-Null
$inputs = New-Item -ItemType Directory -Path (Join-Path $output 'input')
$reports = New-Item -ItemType Directory -Path (Join-Path $output 'analysis')
$rows = @()
foreach ($name in $names) {
    $source = Join-Path $project ("Library/ScriptAssemblies/$name.dll")
    if (!(Test-Path -LiteralPath $source)) {
        $rows += [pscustomobject]@{ Assembly=$name; Status='missing'; Source=$source }
        continue
    }
    $snapshot = Join-Path $inputs.FullName "$name.dll"
    $bytes = [IO.File]::ReadAllBytes($source)
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
    [IO.File]::WriteAllBytes($snapshot,$bytes)
    $json = (& dotnet $cli analyze $snapshot) -join [Environment]::NewLine
    if ($LASTEXITCODE -ne 0) { throw "Analysis failed for $name" }
    $report = $json | ConvertFrom-Json
    if ($report.Sha256 -ne $hash -or (Get-FileHash -LiteralPath $source).Hash -ne $hash) {
        throw "Input changed during snapshot: $name"
    }
    [IO.File]::WriteAllText((Join-Path $reports.FullName "$name.json"),$json,[Text.UTF8Encoding]::new($false))
    $rows += [pscustomobject]@{
        Assembly=$name; Status='analyzed'; Source=$source; Sha256=$hash
        SourceLastWriteTimeUtc=(Get-Item -LiteralPath $source).LastWriteTimeUtc.ToString('O')
        Methods=$report.MethodsWithBodies; ObfuscationEligible=$report.ObfuscationEligible
        IntegerVmEligible=$report.IntegerVmEligible
        AssemblyBlockers=$report.AssemblyBlockers
    }
}
$summary = [pscustomobject]@{
    Project=$project; ObservedUtc=[DateTime]::UtcNow.ToString('O')
    ConfiguredEditor=(Get-Content -LiteralPath (Join-Path $project 'ProjectSettings/ProjectVersion.txt') -First 1)
    Scope='Cached Library DLL snapshots; not rebuilt and not verified against current source or a release Player. Static eligibility is not runtime or security acceptance.'
    Assemblies=$rows
}
[IO.File]::WriteAllText((Join-Path $output 'summary.json'),($summary | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
$rows | Format-Table Assembly,Status,Methods,ObfuscationEligible,IntegerVmEligible -AutoSize
Write-Output "Audit: $output"
