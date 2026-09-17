param(
    [string]$Source='C:/Program Files (x86)/JuniorCoder',
    [string]$Project='C:/Users/servak/Documents/JunCod/JuniorCoder'
)
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Source=(Resolve-Path -LiteralPath $Source).Path
$cli=Join-Path $root 'src/Durevo.Cli/bin/Release/net10.0/Durevo.Cli.dll'
$run=Join-Path $root ('artifacts/wide-prototype-'+[guid]::NewGuid().ToString('N'))
$staging=Join-Path $run 'building'
$final=Join-Path $run 'protected'
New-Item -ItemType Directory -Path $run,$staging | Out-Null
$managed=Join-Path $Source 'JuniorCoder_Data/Managed'
$all=Get-ChildItem -LiteralPath $Source -Recurse -Force
if($all|Where-Object{($_.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0}){throw 'Linked input is unsupported.'}
$sourceFiles=@($all|Where-Object{-not $_.PSIsContainer -and -not($_.DirectoryName -eq $Source -and $_.Name -like 'unins*')})
$inventory=@($sourceFiles|ForEach-Object{[pscustomobject]@{Path=[IO.Path]::GetRelativePath($Source,$_.FullName).Replace('\','/');Size=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
$inventory|ConvertTo-Json -Depth 4|Set-Content (Join-Path $run 'input-inventory.json') -Encoding utf8
Get-ChildItem -LiteralPath $Source -Force|Where-Object{$_.Name -notlike 'unins*'}|Copy-Item -Destination $staging -Recurse
foreach($f in $inventory){if((Get-FileHash -LiteralPath (Join-Path $staging $f.Path)).Hash -ne $f.Sha256){throw 'Initial copy differs from source.'}}
$names=@(Get-ChildItem (Join-Path $Project 'Assets/JuniorCoder') -Filter '*.asmdef' -Recurse|ForEach-Object{(Get-Content $_.FullName -Raw|ConvertFrom-Json).name})
$names+=@('JuniorCoder.Libs','Assembly-CSharp')
$names=@($names|Sort-Object -Unique|Where-Object{Test-Path (Join-Path $managed ($_+'.dll'))})
$reports=@()
$removed=@()
foreach($name in $names){
    $inputDll=Join-Path $managed ($name+'.dll')
    $json=& dotnet $cli analyze $inputDll
    if($LASTEXITCODE -ne 0){throw "Analysis failed: $name"}
    $a=($json|Out-String)|ConvertFrom-Json
    [IO.File]::WriteAllText((Join-Path $run ($name+'.analysis.json')),($json -join [Environment]::NewLine))
    $selected=@($a.Methods|Where-Object{$_.ObfuscationEligible}|Select-Object -ExpandProperty Signature)
    if($a.AssemblyBlockers.Count -ne 0 -or $selected.Count -eq 0){throw "Assembly cannot be protected by this broad profile: $name"}
    $list=Join-Path $run ($name+'.methods.txt')
    [IO.File]::WriteAllLines($list,[string[]]$selected,[Text.UTF8Encoding]::new($false))
    $transformed=Join-Path $run ($name+'.transform')
    $result=& dotnet $cli protect $inputDll $transformed $list
    if($LASTEXITCODE -ne 0){throw "Transformation failed: $name"}
    $protection=($result|Out-String)|ConvertFrom-Json
    Copy-Item -LiteralPath (Join-Path $transformed ($name+'.dll')) -Destination (Join-Path $staging ('JuniorCoder_Data/Managed/'+$name+'.dll'))
    foreach($suffix in @('.pdb','.dll.mdb')){
        $relative='JuniorCoder_Data/Managed/'+$name+$suffix
        $sidecar=Join-Path $staging $relative
        if(Test-Path -LiteralPath $sidecar){
            if(-not [IO.Path]::GetFullPath($sidecar).StartsWith([IO.Path]::GetFullPath($staging)+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected sidecar path'}
            Remove-Item -LiteralPath $sidecar
            $removed+=$relative
        }
    }
    $reports+=[pscustomobject]@{Assembly=$name;TotalBodies=$a.MethodsWithBodies;Protected=$selected.Count;Skipped=@($a.Methods|Where-Object{$_.Instructions -gt 0 -and -not $_.ObfuscationEligible}|Select-Object Signature,ObfuscationBlockers);Protection=$protection}
    Write-Output "$name : $($selected.Count)/$($a.MethodsWithBodies)"
}
# Match the existing CodeState.BuildFromManagedAsync wire format and filename convention.
$targetManaged=Join-Path $staging 'JuniorCoder_Data/Managed'
$codeFiles=@(Get-ChildItem -LiteralPath $targetManaged -Filter '*.dll'|Sort-Object Name|ForEach-Object{[pscustomobject]@{path=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant();size=$_.Length}})
New-Item -ItemType Directory -Force -Path (Join-Path $staging 'State')|Out-Null
[IO.File]::WriteAllText((Join-Path $staging 'State/code_manifest_win.json'),([pscustomobject]@{files=$codeFiles}|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
$allowed=@($names|ForEach-Object{'JuniorCoder_Data/Managed/'+$_+'.dll'})+@('State/code_manifest_win.json')
$changes=@()
foreach($f in $inventory){
    if((Get-FileHash -LiteralPath (Join-Path $Source $f.Path)).Hash -ne $f.Sha256){throw "Source changed: $($f.Path)"}
    if($removed -contains $f.Path){continue}
    $h=(Get-FileHash -LiteralPath (Join-Path $staging $f.Path)).Hash
    if($h -ne $f.Sha256){
        if($allowed -notcontains $f.Path){throw "Unexpected changed file: $($f.Path)"}
        $changes+=[pscustomobject]@{Path=$f.Path;Before=$f.Sha256;After=$h}
    }
}
$totals=[pscustomobject]@{
    Mode='Broad basic IL obfuscation; names/contracts preserved; no full architecture concealment claim'
    Source=$Source;Output=$final;Assemblies=$reports.Count
    ProtectedMethods=($reports|Measure-Object Protected -Sum).Sum
    TotalBodies=($reports|Measure-Object TotalBodies -Sum).Sum
    Changes=$changes;RemovedSymbols=$removed;Modules=$reports
    Acceptance='Build/file-integrity checks only; gameplay, performance, update round-trip remain unverified.'
}
$totals|ConvertTo-Json -Depth 12|Set-Content (Join-Path $run 'build-report.json') -Encoding utf8
Move-Item -LiteralPath $staging -Destination $final
Write-Output "OUTPUT=$final"
Write-Output "METHODS=$($totals.ProtectedMethods)/$($totals.TotalBodies)"
