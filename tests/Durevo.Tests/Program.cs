using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Fixture;
using Mono.Cecil;
using Mono.Cecil.Cil;

if (args is ["--write-license-vector", var vectorPath]) { LicenseVector.Write(vectorPath); return 0; }
if (args is ["--write-mono-fixtures", var fixturePath]) { DependencyBoundaryProbe.WriteMonoFixtures(fixturePath); return 0; }
if (args is ["--probe-juniorcoder-analyzer", var analyzerInput, var analyzerOutput]) { JuniorCoderAnalyzerProbe.Run(analyzerInput, analyzerOutput); return 0; }
if (args is ["--probe-juniorcoder-strings", var stringInput, var stringOutput]) { JuniorCoderStringProbe.Run(stringInput, stringOutput); return 0; }
if (args is ["--write-mono-fixtures", var gameFixtures, "--game-strings", var gameAssembly]) { DependencyBoundaryProbe.WriteMonoFixtures(gameFixtures, gameAssembly); return 0; }
if (args is ["--probe-juniorcoder-cipher", var cipherInput, var cipherOutput]) {
    if (Directory.Exists(cipherOutput)) throw new IOException("Output must be new.");
    ExceptionFixtures.Write(cipherOutput, cipherInput);
    int checks = ExceptionProbe.Run(cipherOutput);
    File.WriteAllText(Path.Combine(cipherOutput, "execution.txt"), "PASS: " + checks + " comparisons.");
    return 0;
}
if (args is ["--write-cipher-fixtures", var exceptionOutput, var licenseAssembly]) {
    ExceptionFixtures.WriteCipher(exceptionOutput, licenseAssembly); return 0;
}
if (args is ["--probe-juniorcoder-release", var releaseSnapshots, var releaseEvidence, var releaseCli, var releaseNative]) {
    JuniorCoderReleaseProbe.Run(releaseSnapshots, releaseEvidence, releaseCli, releaseNative); return 0;
}
if (args is ["--verified-native-probe", var verifiedNativePath]) { VerifiedNativeSuite.Run(verifiedNativePath, false); return 0; }
if (args is ["--verified-native-probe", var poisonedNativePath, "--poison-name"]) { VerifiedNativeSuite.Run(poisonedNativePath, true); return 0; }
if (args is ["--write-verified-native-fixtures", var verifiedFixtures, var verifiedLibrary]) { VerifiedNativeFixtures.Write(verifiedFixtures, verifiedLibrary); return 0; }
int assertions = 0;
void Assert(bool condition, string message)
{
    assertions++;
    if (!condition) throw new Exception(message);
}
void Reject(Action action, string message)
{
    bool failed = false;
    try { action(); } catch (ArgumentException) { failed = true; }
    catch (InvalidOperationException) { failed = true; }
    catch (NotSupportedException) { failed = true; }
    Assert(failed, message);
}
object? Invoke(Type t, string name, params object[] args)
{
    try { return t.GetMethod(name)!.Invoke(null, args); }
    catch (TargetInvocationException e) { return e.InnerException!.GetType().FullName; }
}
var root = Path.Combine(Path.GetTempPath(), "durevo-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    var input = typeof(Cases).Assembly.Location;
    var before = SHA256.HashData(File.ReadAllBytes(input));
    string[] selection;
    using (var source = ModuleDefinition.ReadModule(input))
        selection = Protector.Methods(source).Where(m => m.DeclaringType.FullName == typeof(Cases).FullName
            && m.Name != "Unsupported").Select(m => m.FullName).ToArray();
    string? firstHash = null;
    for (int round = 0; round < 64; round++)
    {
        string output = Path.Combine(root, "protected-" + round + ".dll");
        var report = Protector.Protect(input, output, selection);
        Assert(report.Methods == selection.Length && report.Strings > 0 && report.Integers > 0
            && report.Blocks > selection.Length, "Missing transformations");
        if (firstHash is not null) Assert(report.OutputSha256 != firstHash, "No release diversification");
        firstHash = report.OutputSha256;
        using (var module = ModuleDefinition.ReadModule(output))
        {
            
            Assert(module.Assembly.Name.Name == "Durevo.Fixture", "Identity changed");
            Assert(!Protector.Methods(module).Where(m => selection.Contains(m.FullName))
                .SelectMany(m => m.Body.Instructions).Any(i => i.OpCode.Code == Code.Ldstr
                    && (string)i.Operand == "Durevo-private-alpha"), "Plaintext literal remains in selected IL");
        }
        var context = new AssemblyLoadContext("protected-" + round, isCollectible: true);
        try
        {
            var target = context.LoadFromAssemblyPath(output).GetType(typeof(Cases).FullName!)!;
            var random = new Random(20260916);
            foreach (var x in new[] { int.MinValue, int.MaxValue, -239, -1, 0, 1, 239 }
                .Concat(Enumerable.Range(0, 200).Select(_ => (int)random.NextInt64(int.MinValue, (long)int.MaxValue + 1))))
            {
                int y = unchecked(x * 17);
                Assert(Equals(Invoke(target, "Arithmetic", x, y), Cases.Arithmetic(x, y)), "Arithmetic mismatch");
                Assert(Equals(Invoke(target, "Branches", x), Cases.Branches(x)), $"Loop/branch mismatch x={x}: actual={Invoke(target, "Branches", x)} expected={Cases.Branches(x)}");
                Assert(Equals(Invoke(target, "Wide", x), Cases.Wide(x)), "Wide mismatch");
                Assert(Equals(Invoke(target, "Divide", x), Invoke(typeof(Cases), "Divide", x)), "Exception mismatch");
                Assert(Equals(Invoke(target, "Checked", x), Invoke(typeof(Cases), "Checked", x)), "Overflow mismatch");
            }
            for (int x = -2; x < 10; x++)
                Assert(Equals(Invoke(target, "Switch", x), Cases.Switch(x)), "UTF16/switch mismatch");
            Assert(Equals(Invoke(target, "Interned"), true), "String interning changed");
        }
        finally { context.Unload(); }
        Reject(() => Protector.Protect(input, output, selection), "Output overwrite accepted");
        Reject(() => Protector.Protect(output, output + ".again", selection), "Repeated protection accepted");
    }
    Assert(before.SequenceEqual(SHA256.HashData(File.ReadAllBytes(input))), "Input mutated");
    Reject(() => Protector.Protect(input, input, selection), "In-place edit accepted");
    Reject(() => Protector.Protect(input, Path.Combine(root, "empty.dll"), []), "Empty selection accepted");
    Reject(() => Protector.Protect(input, Path.Combine(root, "missing.dll"), ["not a method"]), "Missing method accepted");
    Reject(() => Protector.Protect(input, Path.Combine(root, "duplicate.dll"), [selection[0], selection[0]]), "Duplicates accepted");
    Reject(() => Protector.Protect(input, Path.Combine(root, "eh.dll"),
        ["System.Int32 Durevo.Fixture.Cases::Unsupported(System.Int32)"], virtualize: true), "VM exception handler accepted");
    Assert(!File.Exists(Path.Combine(root, "eh.dll")), "Rejected transform published output");
    assertions += ExceptionRegionSuite.Run(root);
    string exceptionFixtures = Path.Combine(root, "exception-portable");
    ExceptionFixtures.Write(exceptionFixtures);
    assertions += ExceptionProbe.Run(exceptionFixtures);
    assertions += AnalysisSuite.Run(root);
    assertions += ArchitectureSuite.Run(root);
    assertions += GenericIdentitySuite.Run(root);
    assertions += StackEdgeSuite.Run(root);
    assertions += StringVmSuite.Run(root, native: false);
    assertions += VmSuite.Run(input, root);
    assertions += EncryptedVmSuite.Run(root, native: false);
    assertions += MethodKeySuite.Run(root, native: false);
    assertions += LicenseSuite.Run();
    assertions += ProgramKeyGrantSuite.Run();
    assertions += LicensedRecoveryProbe.Run(root);
    assertions += LicenseVector.Check();
    assertions += ReleaseSuite.Run(root);
    assertions += ReleaseBuildSuite.Run(root);
    assertions += ManagedImageSuite.Run(root);
    assertions += ManagedGraphSuite.Run(root);
    assertions += DependencyBoundaryProbe.Run(root);
    int cliFlag = Array.IndexOf(args, "--release-cli");
    if (cliFlag >= 0) { if (cliFlag + 1 >= args.Length) throw new ArgumentException("CLI assembly path required."); assertions += ReleaseCliSuite.Run(root, args[cliFlag + 1]); }
    if (args.Contains("--native")) { assertions += MethodKeySuite.Run(root, native: true); assertions += MethodKeySuite.Run(root, native: true, verified: true); assertions += NativeArtifactSuite.Run(); assertions += EncryptedVmSuite.Run(root, native: true); assertions += NativeSuite.Run(); assertions += NativeEncryptedSuite.Run(); assertions += StringVmSuite.Run(root, native: true); assertions += LicensedRecoveryProbe.Run(root, native: true); assertions += VmSuite.Run(input, root, native: true); assertions += VerifiedNativeSuite.Run(Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "durevo_vm.dll" : "libdurevo_vm.so"), false); }
    Console.WriteLine($"PASS: {assertions} assertions; 64 obfuscated, 16 managed VM and {(args.Contains("--native") ? 16 : 0)} native VM assemblies actually executed.");
    return 0;
}
catch (Exception e) { Console.Error.WriteLine(e); return 1; }
finally
{
    // Collectible loads may hold files briefly on Windows. Only this uniquely created test tree is removed.
    GC.Collect(); GC.WaitForPendingFinalizers();
    try { Directory.Delete(root, recursive: true); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Console.WriteLine("Test artifacts retained: " + root); }
}
