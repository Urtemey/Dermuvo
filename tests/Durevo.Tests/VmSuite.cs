using System.Reflection;
using System.Runtime.Loader;
using Durevo.Core;
using Durevo.Fixture;
using Mono.Cecil;

internal static class VmSuite
{
    internal static int Run(string input, string root, bool native = false)
    {
        int checks = 0;
        string[] names = ["Arithmetic", "Branches", "Divide", "Checked", "CheckedUnsignedAdd", "CheckedUnsignedSub", "CheckedUnsignedMul"];
        string[] selection;
        using (var module = ModuleDefinition.ReadModule(input))
            selection = Protector.Methods(module).Where(m => names.Contains(m.Name)).Select(m => m.FullName).ToArray();
        for (int round = 0; round < 16; round++)
        {
            string output = Path.Combine(root, (native ? "native-" : "virtualized-") + round + ".dll");
            Protector.Protect(input, output, selection, virtualize: true, native: native);
            using (var recoveredModule = ModuleDefinition.ReadModule(output))
            {
                var recovered = RecoveryProbe.Recover(Protector.Methods(recoveredModule).Single(m => m.Name == "Branches"));
                if (recovered.Length == 0 || !recovered.Contains(24)) throw new Exception("Baseline recovery probe failed unexpectedly.");
                checks++;
            }
            var context = new AssemblyLoadContext("vm-"+round, isCollectible: true);
            try
            {
                var type = context.LoadFromAssemblyPath(output).GetType(typeof(Cases).FullName!)!;
                var random = new Random(round);
                foreach (int value in new[] { int.MinValue, int.MaxValue, 0, 1, -1, -239, 239 }
                    .Concat(Enumerable.Range(0, 200).Select(_ => (int)random.NextInt64(int.MinValue, (long)int.MaxValue+1))))
                    foreach (string name in names)
                    {
                        object[] args = typeof(Cases).GetMethod(name)!.GetParameters().Length == 2 ? [value, unchecked(value*17)] : [value];
                        var expected = Invoke(typeof(Cases), name, args);
                        var actual = Invoke(type, name, args);
                        if (!Equals(expected, actual))
                            throw new Exception($"VM {name}({value}): expected {expected}, actual {actual}");
                        checks++;
                    }
            }
            finally { context.Unload(); }
        }
        using (var module = ModuleDefinition.ReadModule(input))
        {
            try
            {
                IntegerVirtualizer.Transform(module, Protector.Methods(module).Single(m => m.Name == "Switch"));
                throw new Exception("VM accepted string method.");
            }
            catch (NotSupportedException) { checks++; }
            try
            {
                IntegerVirtualizer.Transform(module, Protector.Methods(module).Single(m => m.Name == "Unsupported"));
                throw new Exception("VM accepted exception handlers.");
            }
            catch (NotSupportedException) { checks++; }
        }
        return checks;
    }
    static object? Invoke(Type type, string name, object[] args)
    {
        try { return type.GetMethod(name)!.Invoke(null, args); }
        catch (TargetInvocationException e) { return e.InnerException!.GetType().FullName; }
    }
}
