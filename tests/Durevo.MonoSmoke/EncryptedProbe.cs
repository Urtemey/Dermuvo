using System;
using System.IO;
using System.Reflection;
using Durevo.Runtime;

internal static class EncryptedProbe
{
    internal static void Run(string root) { RunVariant(root, false); }
    internal static void RunNative(string root) { RunVariant(root, true); }
    private static void RunVariant(string root, bool native)
    {
        var assembly = Assembly.Load(File.ReadAllBytes(Path.Combine(root,native ? "encrypted-native-release" : "encrypted-release","Durevo.Fixture.dll")));
        var method = assembly.GetType("Durevo.Fixture.Cases").GetMethod("Arithmetic");
        Action requireDenied = () => {
            bool rejected = false;
            try { method.Invoke(null, new object[] { 7,13 }); }
            catch (TargetInvocationException error) { if (error.InnerException is UnauthorizedAccessException) rejected = true; else throw; }
            if (!rejected) throw new Exception("Encrypted method executed without a provisioned key.");
        };
        requireDenied();
        byte[] key = File.ReadAllBytes(Path.Combine(root,"synthetic-program.vmkey"));
        try
        {
            long now = 1500000;
            byte[] grant = File.ReadAllBytes(Path.Combine(root,"program-grant.bin"));
            byte[] license = File.ReadAllBytes(Path.Combine(root,"program-license.bin"));
            byte[] publicKey = File.ReadAllBytes(Path.Combine(root,"program-public.bin"));
            string keyId = File.ReadAllText(Path.Combine(root,"program-key-id.txt"));
            using (native
                ? ProgramKeyGrant.ActivateNative(grant,license,key,publicKey,keyId,"JuniorCoder","synthetic-player",0,1,
                    () => DateTimeOffset.FromUnixTimeSeconds(now))
                : ProgramKeyGrant.Activate(grant,license,key,publicKey,keyId,"JuniorCoder","synthetic-player",0,1,
                    () => DateTimeOffset.FromUnixTimeSeconds(now)))
            {
                Array.Clear(key,0,key.Length);
                foreach (int value in new[] { int.MinValue,int.MaxValue,-1,0,1,239 })
                {
                    int expected = unchecked((value * 7919 + 13) ^ -123456789);
                    if (!Equals(method.Invoke(null,new object[] { value,13 }),expected))
                        throw new Exception("Encrypted method result differs.");
                }
                now = 2000000; requireDenied();
                now = 1500000; requireDenied();
            }
        }
        finally { Array.Clear(key,0,key.Length); }
        requireDenied();
        if (File.Exists(Path.Combine(root,"game-string-original.dll"))) RunReal(root,native);
        Console.WriteLine("PASS: " + (native ? "native" : "managed") + " signed key grant enables encrypted VM; expiry revokes subsequent calls and does not resurrect on clock rollback.");
    }
    private static void RunReal(string root, bool native)
    {
        const string typeName = "JuniorCoder.Scripts.Game.LogicLua.PythonCodeHandlerBeforeLaunch";
        const string methodName = "HasMultipleTopLevelArguments";
        var original = Assembly.Load(File.ReadAllBytes(Path.Combine(root,"game-string-original.dll")))
            .GetType(typeName).GetMethod(methodName, BindingFlags.Static | BindingFlags.NonPublic);
        var target = Assembly.Load(File.ReadAllBytes(Path.Combine(root,native ? "game-string-native.dll" : "game-string-managed.dll")))
            .GetType(typeName).GetMethod(methodName, BindingFlags.Static | BindingFlags.NonPublic);
        string[] samples = { null, "", "say('hello')", "say('hello',2)", "say('a,b')", "say(f(1,2))",
            "say(f(1,2),3)", "say([1,2])", "say({1:2,3:4})", "say('😀,я')", "say('😀,я',1)",
            "say('\0,\ud800')", "say('\0,\ud800',1)", "say(", "say(a,b" };
        if (!Equals(InvokeReal(original,samples[2]),false) || !Equals(InvokeReal(original,samples[3]),true))
            throw new Exception("Actual parser baseline failed.");
        if (!Equals(InvokeReal(target,samples[3]),typeof(UnauthorizedAccessException).FullName))
            throw new Exception("Actual protected parser ran without key.");
        byte[] key = File.ReadAllBytes(Path.Combine(root,"synthetic-program.vmkey"));
        byte[] grant = File.ReadAllBytes(Path.Combine(root,"program-grant.bin"));
        byte[] license = File.ReadAllBytes(Path.Combine(root,"program-license.bin"));
        byte[] publicKey = File.ReadAllBytes(Path.Combine(root,"program-public.bin"));
        string keyId = File.ReadAllText(Path.Combine(root,"program-key-id.txt"));
        long now = 1500000;
        try
        {
            using (native
                ? ProgramKeyGrant.ActivateNative(grant,license,key,publicKey,keyId,"JuniorCoder","synthetic-player",0,1,
                    () => DateTimeOffset.FromUnixTimeSeconds(now))
                : ProgramKeyGrant.Activate(grant,license,key,publicKey,keyId,"JuniorCoder","synthetic-player",0,1,
                    () => DateTimeOffset.FromUnixTimeSeconds(now)))
            {
                Array.Clear(key,0,key.Length);
                foreach (string text in samples)
                    if (!Equals(InvokeReal(target,text),InvokeReal(original,text)))
                        throw new Exception("Actual protected parser changed behavior.");
                now = 2000000;
                if (!Equals(InvokeReal(target,samples[3]),typeof(UnauthorizedAccessException).FullName))
                    throw new Exception("Actual parser ignored expiry.");
            }
        }
        finally { Array.Clear(key,0,key.Length); }
        Console.WriteLine("PASS: " + (native ? "native" : "managed") + " actual cooperative string VM; original behavior and license expiry preserved.");
    }
    private static object InvokeReal(MethodInfo method, string text)
    {
        try { return method.Invoke(null,new object[] { text }); }
        catch (TargetInvocationException error) { return error.InnerException.GetType().FullName; }
    }

}
