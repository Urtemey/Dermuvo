using System;
using System.IO;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEditor.SceneManagement;
using UnityEngine;
using UnityEngine.Rendering;

public static class DurevoPlayerBuilder
{
    public static void PreparePlugins()
    {
        var importer = (PluginImporter)AssetImporter.GetAtPath("Assets/Durevo/Plugins/Mono.Cecil.dll");
        if (importer == null) throw new Exception("Mono.Cecil plugin was not imported.");
        importer.SetExcludeEditorFromAnyPlatform(true);
        importer.SetCompatibleWithEditor(false);
        importer.SaveAndReimport();
        ConfigureNative("Assets/Durevo/Plugins/Native/durevo_vm.dll", BuildTarget.StandaloneWindows64);
        ConfigureNative("Assets/Durevo/Plugins/Native/libdurevo_vm.so", BuildTarget.StandaloneLinux64);
        AssetDatabase.SaveAssets();
    }
    private static void ConfigureNative(string path, BuildTarget target)
    {
        var importer = AssetImporter.GetAtPath(path) as PluginImporter;
        if (importer == null) return;
        importer.SetCompatibleWithAnyPlatform(false);
        importer.SetCompatibleWithEditor(false);
        importer.SetCompatibleWithPlatform(BuildTarget.StandaloneWindows64, false);
        importer.SetCompatibleWithPlatform(BuildTarget.StandaloneLinux64, false);
        importer.SetCompatibleWithPlatform(target, true);
        importer.SetPlatformData(target, "CPU", "x86_64");
        importer.SaveAndReimport();
    }
    public static void BuildWindows() { Build(BuildTarget.StandaloneWindows64, "unity-player-win", "DurevoPlayerSmoke.exe"); }
    public static void BuildLinux() { Build(BuildTarget.StandaloneLinux64, "unity-player-linux", "DurevoPlayerSmoke.x86_64"); }
    private static void Build(BuildTarget target, string folder, string executable)
    {
        PlayerSettings.SetScriptingBackend(NamedBuildTarget.Standalone, ScriptingImplementation.Mono2x);
        PlayerSettings.SetApiCompatibilityLevel(NamedBuildTarget.Standalone, ApiCompatibilityLevel.NET_Standard);
        PlayerSettings.SetManagedStrippingLevel(NamedBuildTarget.Standalone, ManagedStrippingLevel.Disabled);
        PlayerSettings.companyName = "DurevoTest";
        PlayerSettings.productName = "DurevoPlayerSmoke";
        GraphicsSettings.defaultRenderPipeline = null;
        QualitySettings.renderPipeline = null;
        var scene = EditorSceneManager.NewScene(NewSceneSetup.EmptyScene, NewSceneMode.Single);
        const string scenePath = "Assets/Durevo/Smoke.unity";
        if (!EditorSceneManager.SaveScene(scene, scenePath)) throw new Exception("Scene save failed.");
        string output = Path.GetFullPath(Path.Combine(Application.dataPath, "../../../artifacts", folder, executable));
        Directory.CreateDirectory(Path.GetDirectoryName(output));
        AssetDatabase.SaveAssets();
        var report = BuildPipeline.BuildPlayer(new BuildPlayerOptions {
            scenes = new[] { scenePath }, locationPathName = output, target = target,
            options = BuildOptions.Development
        });
        if (report.summary.result != BuildResult.Succeeded)
            throw new Exception("Player build failed: " + report.summary.result);
        Debug.Log("DUREVO_BUILD_OK " + output);
    }
}
