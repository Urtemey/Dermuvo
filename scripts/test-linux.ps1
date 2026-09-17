$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$image = 'mcr.microsoft.com/dotnet/sdk@sha256:4beef5b8919dcaa2dc924233bd069257e883cc7a061e09088a97d152d6a48510'
docker run --rm --mount "type=bind,source=$projectRoot,target=/source,readonly" $image sh -c 'set -eu; mkdir -p /tmp/durevo/tests; cp -r /source/src /source/third-party /source/Directory.Build.props /source/global.json /source/NuGet.Config /tmp/durevo/; cp -r /source/tests/Durevo.Tests /source/tests/Durevo.Fixture /tmp/durevo/tests/; cd /tmp/durevo; dotnet restore tests/Durevo.Tests --locked-mode; dotnet run --project tests/Durevo.Tests -c Release --no-restore'
if ($LASTEXITCODE -ne 0) { throw "Linux test failed: $LASTEXITCODE" }
