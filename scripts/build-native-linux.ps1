$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$nativeRoot = Join-Path $projectRoot 'native'
$output = Join-Path $projectRoot 'artifacts/native-linux-x64'
New-Item -ItemType Directory -Force $output | Out-Null
docker build -t durevo-native-tests:local $nativeRoot
if ($LASTEXITCODE -ne 0) { throw 'Native build image failed.' }
docker run --rm --mount "type=bind,source=$nativeRoot,target=/source,readonly" --mount "type=bind,source=$output,target=/output" durevo-native-tests:local sh -c 'set -eu; gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -fvisibility=hidden -shared /source/durevo_encrypted.c -lcrypto -o /output/libdurevo_vm.so; ldd /output/libdurevo_vm.so'
if ($LASTEXITCODE -ne 0) { throw 'Linux native build failed.' }
