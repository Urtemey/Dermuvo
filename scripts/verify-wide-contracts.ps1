param([Parameter(Mandatory=$true)][string]$Run)
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Run=(Resolve-Path -LiteralPath $Run).Path
$build=Get-Content (Join-Path $Run 'build-report.json') -Raw|ConvertFrom-Json
$cli=Join-Path $root 'src/Durevo.Cli/bin/Release/net10.0/Durevo.Cli.dll'
function Normalize-Type($t) {
    [pscustomobject]@{
        Name=$t.Name;Base=$t.BaseType
        Interfaces=@($t.Interfaces|Sort-Object -CaseSensitive)
        Attributes=@($t.Attributes|Sort-Object -CaseSensitive)
        Fields=@($t.Fields|Sort-Object -CaseSensitive)
        Properties=@($t.Properties|Sort-Object -CaseSensitive)
        Events=@($t.Events|Sort-Object -CaseSensitive)
        Methods=@($t.Methods|ForEach-Object{$_.Signature+'|'+$_.Visibility}|Sort-Object -CaseSensitive)
    }|ConvertTo-Json -Depth 8 -Compress
}
$results=@()
foreach($entry in $build.Modules){
    $relative='JuniorCoder_Data/Managed/'+$entry.Assembly+'.dll'
    $before=(& dotnet $cli analyze-architecture (Join-Path $build.Source $relative)|Out-String)|ConvertFrom-Json
    if($LASTEXITCODE -ne 0){throw 'Original inspection failed'}
    $after=(& dotnet $cli analyze-architecture (Join-Path $build.Output $relative)|Out-String)|ConvertFrom-Json
    if($LASTEXITCODE -ne 0){throw 'Protected inspection failed'}
    if($before.Assembly -cne $after.Assembly){throw 'Assembly identity changed'}
    if(($before.References -join '|') -cne ($after.References -join '|')){throw "References changed: $($entry.Assembly)"}
    $byName=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach($t in $after.Types){$byName.Add($t.Name,$t)}
    foreach($t in $before.Types){
        if(-not $byName.ContainsKey($t.Name) -or (Normalize-Type $t) -cne (Normalize-Type $byName[$t.Name])){throw "Named contract changed: $($t.Name)"}
    }
    foreach($name in $before.Resources){if($after.Resources -cnotcontains $name){throw 'Original resource name lost'}}
    $results+=[pscustomobject]@{Assembly=$entry.Assembly;Types=$before.Types.Count;Methods=@($before.Types.Methods).Count;Status='PASS'}
    Write-Output "CONTRACTS PASS: $($entry.Assembly)"
}
$manifest=Get-Content (Join-Path $build.Output 'State/code_manifest_win.json') -Raw|ConvertFrom-Json
foreach($f in $manifest.files){
    $file=Get-Item -LiteralPath (Join-Path $build.Output ('JuniorCoder_Data/Managed/'+$f.path))
    if($file.Length -ne $f.size -or (Get-FileHash -LiteralPath $file.FullName).Hash -ine $f.sha256){throw "Code manifest mismatch: $($f.path)"}
}
[pscustomobject]@{Assemblies=$results;CodeManifestEntries=$manifest.files.Count;Scope='Names, signatures, field/property/event declarations, base/interface/attribute type names and assembly references. Not full reflection/serialization or gameplay acceptance.'}|
    ConvertTo-Json -Depth 7|Set-Content (Join-Path $Run 'contract-checks.json') -Encoding utf8
