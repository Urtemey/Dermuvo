$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$vswhere = "${env:ProgramFiles(x86)}/Microsoft Visual Studio/Installer/vswhere.exe"
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw 'MSVC x64 tools required.' }
$output = Join-Path $projectRoot 'artifacts/native-win-x64'
New-Item -ItemType Directory -Force $output | Out-Null
$command = '"' + $vs + '\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul && cl /nologo /std:c11 /O2 /W4 /WX /LD /MT /guard:cf "' + $projectRoot + '\native\durevo_encrypted.c" /Fe:"' + $output + '\durevo_vm.dll" /Fo:"' + $output + '\durevo_vm.obj" /link bcrypt.lib /DYNAMICBASE /NXCOMPAT /IMPLIB:"' + $output + '\durevo_vm.lib"'
& $env:ComSpec /d /s /c $command
if ($LASTEXITCODE -ne 0) { throw "Native compilation failed: $LASTEXITCODE" }
