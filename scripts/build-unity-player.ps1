param(
    [string]$UnityVersion = '6000.3.22f1',
    [ValidateSet('Windows','Linux')][string]$Target = 'Windows'
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$unityProject = Join-Path $projectRoot 'tests/UnityPlayerSmoke'
if (!(Test-Path -LiteralPath (Join-Path $unityProject 'ProjectSettings/ProjectVersion.txt'))) {
    throw 'Create the UnityPlayerSmoke project using the documented Unity CLI command first.'
}
Push-Location $projectRoot
try {
    dotnet restore Durevo.slnx --locked-mode
    dotnet build Durevo.slnx -c Release --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Durevo build failed.' }
    $scripts = Join-Path $unityProject 'Assets/Durevo'
    $plugins = Join-Path $scripts 'Plugins'
    New-Item -ItemType Directory -Force $plugins | Out-Null
    Copy-Item tests/Durevo.MonoSmoke/Program.cs (Join-Path $scripts 'MonoSmoke.cs')
    Copy-Item tests/Durevo.MonoSmoke/BindingProbe.cs (Join-Path $scripts 'BindingProbe.cs')
    Copy-Item tests/Durevo.MonoSmoke/EncryptedProbe.cs (Join-Path $scripts 'EncryptedProbe.cs')
    Copy-Item tests/Durevo.Tests/Portable/ExceptionProbe.cs (Join-Path $scripts 'ExceptionProbe.cs')
    Copy-Item tests/Durevo.Tests/Portable/VerifiedNativeProbe.cs (Join-Path $scripts 'VerifiedNativeProbe.cs')
    Copy-Item src/Durevo.Runtime/bin/Release/netstandard2.1/Durevo.Runtime.dll $plugins
    Copy-Item src/Durevo.Cli/bin/Release/net10.0/runtime-dependencies/*.dll $plugins
    Copy-Item src/Durevo.Cli/bin/Release/net10.0/runtime-dependencies/*LICENSE* $plugins
    $nativePlugins = Join-Path $plugins 'Native'
    New-Item -ItemType Directory -Force $nativePlugins | Out-Null
    if ($Target -eq 'Windows') {
        & (Join-Path $PSScriptRoot 'build-native-windows.ps1')
        Copy-Item artifacts/native-win-x64/durevo_vm.dll $nativePlugins -Force
    } else {
        & (Join-Path $PSScriptRoot 'build-native-linux.ps1')
        Copy-Item artifacts/native-linux-x64/libdurevo_vm.so $nativePlugins -Force
    }
    $prepareLog = Join-Path $projectRoot 'artifacts/unity-player-prepare.log'
    unity run $unityProject --editor-version $UnityVersion --timeout 300 -- -nographics -executeMethod DurevoPlayerBuilder.PreparePlugins -logFile $prepareLog
    if ($LASTEXITCODE -ne 0) { throw "Unity plugin preparation failed; see $prepareLog" }
    $log = Join-Path $projectRoot ('artifacts/unity-player-build-' + $Target.ToLowerInvariant() + '.log')
    unity run $unityProject --editor-version $UnityVersion --timeout 900 -- -nographics -executeMethod "DurevoPlayerBuilder.Build$Target" -logFile $log
    if ($LASTEXITCODE -ne 0) { throw "Unity $Target build failed; see $log" }
}
finally { Pop-Location }
