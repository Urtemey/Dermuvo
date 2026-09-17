using System;
using UnityEngine;

internal static class DurevoPlayerRunner
{
    [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.AfterSceneLoad)]
    private static void Run()
    {
        int exitCode = 1;
        try
        {
            var args = Environment.GetCommandLineArgs();
            int flag = Array.IndexOf(args, "--durevo-fixtures");
            if (flag < 0 || flag + 1 >= args.Length) throw new ArgumentException("Fixture directory required.");
            if (IntPtr.Size != 8) throw new Exception("Expected a 64-bit Player.");
            Debug.Log("DUREVO_PLAYER_START Unity=" + Application.unityVersion + " platform=" + Application.platform + " pointerSize=" + IntPtr.Size);
            exitCode = MonoSmoke.Main(new[] { args[flag + 1] });
            if (exitCode == 0) EncryptedProbe.RunNative(args[flag + 1]);
            Debug.Log("DUREVO_PLAYER_RESULT exitCode=" + exitCode);
        }
        catch (Exception error) { exitCode = 1; Debug.LogException(error); }
        Application.Quit(exitCode);
    }
}
