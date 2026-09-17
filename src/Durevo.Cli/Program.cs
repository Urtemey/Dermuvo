using Durevo.Core;
using Durevo.Runtime;
using Mono.Cecil;
using System.Security.Cryptography;
using System.Text.Json;

try
{
    if (args.Length == 2 && args[0] == "inspect")
    {
        using var module = ModuleDefinition.ReadModule(args[1]);
        foreach (var method in Protector.Methods(module).Where(m => m.HasBody))
            Console.WriteLine(Protector.MethodIdentity(method));
    }
    else if (args.Length == 2 && args[0] == "inspect-native")
    {
        Console.WriteLine(JsonSerializer.Serialize(NativeArtifactInspector.Inspect(Path.GetFileName(args[1]),
            ReleaseCommands.ReadBounded(args[1], 64 * 1024 * 1024)), new JsonSerializerOptions { WriteIndented = true }));
    }
    else if (args.Length == 2 && args[0] == "analyze-architecture") { Console.WriteLine(JsonSerializer.Serialize(ArchitectureAnalysis.Analyze(args[1]), new JsonSerializerOptions { WriteIndented = true })); }
    else if (args.Length == 2 && args[0] == "analyze")
    {
        Console.WriteLine(JsonSerializer.Serialize(ProtectionAnalysis.Analyze(args[1]),
            new JsonSerializerOptions { WriteIndented = true }));
    }
    else if (args.Length is >= 5 and <= 7 && args[0] == "protect-release") { ProtectedReleaseCommands.Build(args); }
    else if (args.Length is >= 6 and <= 7 && args[0] == "protect-release-keyring") { ProtectedReleaseCommands.Build(args); }
    else if (args.Length == 9 && args[0] == "issue-release-grant") { GrantCommands.IssueRelease(args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8]); }
    else if (args.Length == 6 && args[0] == "issue-program-grant") { GrantCommands.Issue(args[1],args[2],args[3],args[4],args[5]); }
    else if (args.Length == 2 && args[0] == "new-program-key") { ProgramKeyCommands.Create(args[1]); }
    else if (args.Length == 5 && args[0] == "verify-release")
    {
        ReleaseCommands.Verify(args[1], args[2], args[3], args[4]);
    }
    else if (args.Length == 5 && args[0] == "sign-release")
    {
        ReleaseCommands.Sign(args[1], args[2], args[3], args[4]);
    }
    else if ((args.Length == 4 && args[0] is "protect" or "virtualize") || (args.Length == 5 && args[0] is "virtualize-native" or "virtualize-encrypted") || (args.Length == 6 && args[0] is "virtualize-encrypted-native" or "virtualize-encrypted-verified-native"))
    {
        bool native = args[0].EndsWith("-native", StringComparison.Ordinal);
        bool encrypted = args[0].Contains("encrypted", StringComparison.Ordinal);
        using var encryption = encrypted ? ProgramKeyCommands.Read(args[4]) : null;
        bool vm = args[0] != "protect";
        byte[]? nativeBytes = null; string? nativeName = null;
        if (native) {
            nativeName = Path.GetFileName(args[encrypted ? 5 : 4]);
            if (nativeName is not ("durevo_vm.dll" or "libdurevo_vm.so")) throw new ArgumentException("Expected durevo_vm.dll or libdurevo_vm.so.");
            nativeBytes = File.ReadAllBytes(args[encrypted ? 5 : 4]);
            if (nativeBytes.Length == 0) throw new ArgumentException("Native library is empty.");
        }
        var methods = File.ReadAllLines(args[3]).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
        // Publish a complete fresh directory, including the VM dependency when required.
        string destination = Path.GetFullPath(args[2]);
        if (Directory.Exists(destination) || File.Exists(destination))
            throw new IOException("Destination must be a new directory.");
        string parent = Path.GetDirectoryName(destination)!;
        Directory.CreateDirectory(parent);
        string staging = Path.Combine(parent, ".durevo-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging);
        try
        {
            string output = Path.Combine(staging, Path.GetFileName(args[1]));
            if (vm && Path.GetFileName(args[1]).Equals("Durevo.Runtime.dll", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Cannot virtualize the VM runtime itself.");
            var report = Protector.Protect(args[1], output, methods, virtualize: vm, native: native, encryption: encryption, verifiedNative: args[0] == "virtualize-encrypted-verified-native");
            if (vm)
            {
                File.Copy(typeof(IntegerMachine).Assembly.Location, Path.Combine(staging, "Durevo.Runtime.dll"));
                foreach (string dependency in new[] { "BouncyCastle.Cryptography.dll", "BouncyCastle.LICENSE.md", "Mono.Cecil.dll", "Mono.Cecil.LICENSE.txt" })
                    File.Copy(Path.Combine(AppContext.BaseDirectory, "runtime-dependencies", dependency), Path.Combine(staging, dependency));
            }
            if(native) File.WriteAllBytes(Path.Combine(staging, nativeName!), nativeBytes!);
            File.WriteAllText(Path.Combine(staging, "report.json"), JsonSerializer.Serialize(
                new { Mode = args[0], ProgramKeyId = encryption?.KeyId, NativeLibrary = nativeName, NativeSha256 = native ? Convert.ToHexString(SHA256.HashData(nativeBytes!)) : null, RuntimeSha256 = vm ? Convert.ToHexString(SHA256.HashData(
                    File.ReadAllBytes(typeof(IntegerMachine).Assembly.Location))) : null, Protection = report },
                new JsonSerializerOptions { WriteIndented = true }));
            Directory.Move(staging, destination);
            Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        }
        finally
        {
            if(Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
        }
    }
    else
    {
        Console.Error.WriteLine("issue-release-grant <release-root> <slot> <license> <program-key> <issuer.pem> <product> <minimum-revision> <NEW-grant>");
        Console.Error.WriteLine("protect-release-keyring <source-root> <NEW-output-root> <plan.json> <encrypted-issuer.pem> <keyring.json> [native-library]");
        Console.Error.WriteLine("protect-release <source-root> <NEW-output-root> <plan.json> <encrypted-issuer.pem> [program.vmkey [native-library]]");
        Console.Error.WriteLine("sign-release <root> <product> <revision> <encrypted-private-key.pem> | verify-release <root> <public-key.bin> <product> <minimum-revision>");
        Console.Error.WriteLine("issue-program-grant <license.bin> <program.vmkey> <required-feature-bits> <encrypted-issuer.pem> <NEW-grant.bin>");
        Console.Error.WriteLine("virtualize-encrypted-verified-native <input> <NEW-output-directory> <methods.txt> <key.vmkey> <native-library>");
        Console.Error.WriteLine("new-program-key <NEW-key.vmkey> | virtualize-encrypted <input> <NEW-output-directory> <methods.txt> <key.vmkey> | virtualize-encrypted-native <input> <NEW-output-directory> <methods.txt> <key.vmkey> <native-library>");
        Console.Error.WriteLine("Durevo: inspect-native <native-library> | inspect|analyze <assembly> | protect|virtualize <input> <NEW-output-directory> <method-list.txt> | virtualize-native <input> <NEW-output-directory> <method-list.txt> <native-library>");
        return 2;
    }
    return 0;
}
catch (Exception e)
{
    Console.Error.WriteLine(e.GetType().Name + ": " + e.Message);
    return 1;
}
