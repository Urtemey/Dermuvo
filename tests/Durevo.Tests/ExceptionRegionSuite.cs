using System.Reflection;
using System.Runtime.Loader;
using Durevo.Core;
using Durevo.Fixture;
using Mono.Cecil;

internal static class ExceptionRegionSuite
{
    internal static int Run(string root)
    {
        string input = typeof(ExceptionCases).Assembly.Location;
        using var source = ModuleDefinition.ReadModule(input);
        var methods = Protector.Methods(source).Where(m => m.DeclaringType.FullName == typeof(ExceptionCases).FullName && m.HasBody).ToArray();
        var signatures = methods.Select(m => m.FullName).ToArray();
        int checks = 0;
        for (int round = 0; round < 16; round++)
        {
            string output = Path.Combine(root, "exception-regions-" + round + ".dll");
            Protector.Protect(input, output, signatures);
            using (var targetModule = ModuleDefinition.ReadModule(output))
            foreach (var original in methods)
            {
                var target = Protector.Methods(targetModule).Single(m => m.FullName == original.FullName);
                if (!original.Body.ExceptionHandlers.Select(h => h.HandlerType).SequenceEqual(
                    target.Body.ExceptionHandlers.Select(h => h.HandlerType))) throw new Exception("Handler order/type changed.");
                checks++;
                foreach (var handler in target.Body.ExceptionHandlers)
                {
                    var body = target.Body.Instructions;
                    int End(Mono.Cecil.Cil.Instruction? i) => i == null ? body.Count : body.IndexOf(i);
                    if (body.IndexOf(handler.TryStart) < 0 || End(handler.TryEnd) <= body.IndexOf(handler.TryStart)
                        || body.IndexOf(handler.HandlerStart) < 0 || End(handler.HandlerEnd) <= body.IndexOf(handler.HandlerStart))
                        throw new Exception("Invalid exception interval.");
                    checks++;
                }
            }
            var load = new AssemblyLoadContext("exception-regions-" + round, true);
            try
            {
                var target = load.LoadFromAssemblyPath(output).GetType(typeof(ExceptionCases).FullName!)!;
                foreach (string name in new[] { "Nested", "Filter", "Rethrow" })
                foreach (int x in Enumerable.Range(-100, 201).Concat(new[] { int.MinValue, int.MaxValue }))
                {
                    var expected = Observe(typeof(ExceptionCases), name, x);
                    var actual = Observe(target, name, x);
                    if (actual != expected) throw new Exception($"EH semantics changed: {name}({x}): {actual} != {expected}");
                    checks++;
                }
            }
            finally { load.Unload(); }
        }
        Console.WriteLine($"Exception region suite: {checks} handler/filter/finally differential checks.");
        return checks;
    }
    private static (string? Value, string? Error, string? Trace) Observe(Type type, string name, int x)
    {
        string? value = null, error = null;
        try { value = (string?)type.GetMethod(name)!.Invoke(null, new object[] { x }); }
        catch (TargetInvocationException e) { error = e.InnerException!.GetType().FullName + ":" + e.InnerException.Message; }
        return (value, error, (string?)type.GetField("Trace")!.GetValue(null));
    }
}
