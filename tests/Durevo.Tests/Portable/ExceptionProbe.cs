#nullable disable
using System;
using System.IO;
using System.Reflection;

internal static class ExceptionProbe
{
    private static string Observe(Type type, string method, int input)
    {
        string result;
        try { result = "value:" + (string)type.GetMethod(method).Invoke(null, new object[] { input }); }
        catch (TargetInvocationException error) { result = "error:" + error.InnerException.GetType().FullName + ":" + error.InnerException.Message; }
        return result + "|" + (string)type.GetField("Trace").GetValue(null);
    }
    private static string Call(Type type, string method, string input, string secret)
    {
        return (string)type.GetMethod(method).Invoke(null, new object[] { input, secret });
    }
    private static string Outcome(Type type, string method, string input, string secret)
    {
        try { return "value:" + Call(type, method, input, secret); }
        catch (TargetInvocationException error) {
            var argument = error.InnerException as ArgumentException;
            return "error:" + error.InnerException.GetType().FullName + ":" + (argument == null ? "" : argument.ParamName);
        }
    }
    internal static int Run(string root)
    {
        string originalPath = Path.Combine(root, "eh-original.dll");
        if (!File.Exists(originalPath)) throw new Exception("Missing EH fixture.");
        int checks = 0;
        var original = Assembly.Load(File.ReadAllBytes(originalPath)).GetType("Durevo.Fixture.ExceptionCases", true);
        if (Observe(original, "Fault", 0) != "error:System.DivideByZeroException:Attempted to divide by zero.|fault") {
            // Exception message is localized/platform-specific; check the semantic parts only.
            string fault = Observe(original, "Fault", 0);
            if (!fault.StartsWith("error:System.DivideByZeroException:") || !fault.EndsWith("|fault")) throw new Exception("Fault baseline did not run.");
        }
        if (Observe(original, "Fault", 1) != "value:completed|") throw new Exception("Fault ran on successful exit.");
        for (int round = 0; round < 4; round++)
        {
            var target = Assembly.Load(File.ReadAllBytes(Path.Combine(root, "eh-protected-" + round + ".dll"))).GetType(original.FullName, true);
            foreach (var method in new[] { "Nested", "Filter", "Rethrow", "Fault" })
            for (int value = -25; value <= 25; value++)
            {
                if (Observe(original, method, value) != Observe(target, method, value))
                    throw new Exception("EH mismatch: " + method + "(" + value + ")");
                checks++;
            }
        }
        Console.WriteLine("PASS: protected nested handlers, filters and finally; " + checks + " comparisons.");
        string cipherPath = Path.Combine(root, "cipher-original.dll");
        if (!File.Exists(cipherPath)) return checks;
        var cipher = Assembly.Load(File.ReadAllBytes(cipherPath)).GetType("StringCipher", true);
        const string secret = "synthetic-test-secret-not-a-license";
        string[] texts = { "license-test", "кириллица😀", "line\r\nnext", "embedded\0nul", new string('x', 4096) };
        for (int round = 0; round < 4; round++)
        {
            var target = Assembly.Load(File.ReadAllBytes(Path.Combine(root, "cipher-protected-" + round + ".dll"))).GetType("StringCipher", true);
            foreach (var text in texts)
            {
                string baselineCipher = Call(cipher, "EncryptStringAES", text, secret);
                string protectedCipher = Call(target, "EncryptStringAES", text, secret);
                if (Call(target, "DecryptStringAES", baselineCipher, secret) != text ||
                    Call(cipher, "DecryptStringAES", protectedCipher, secret) != text)
                    throw new Exception("Actual license cipher interoperability failed.");
                checks += 2;
                byte[] bytes = Convert.FromBase64String(baselineCipher);
                bytes[bytes.Length - 1] ^= 1;
                foreach (var invalid in new[] { "not base64!", "", null, Convert.ToBase64String(new byte[] { 0, 0 }),
                    Convert.ToBase64String(new byte[] { 16, 0, 0, 0 }), Convert.ToBase64String(bytes) })
                {
                    if (Outcome(cipher, "DecryptStringAES", invalid, secret) != Outcome(target, "DecryptStringAES", invalid, secret))
                        throw new Exception("Actual cipher error behavior changed.");
                    checks++;
                }
                if (Outcome(cipher, "DecryptStringAES", baselineCipher, "wrong") !=
                    Outcome(target, "DecryptStringAES", baselineCipher, "wrong"))
                    throw new Exception("Wrong-secret behavior changed.");
                checks++;
            }
            foreach (var invalid in new[] { "", (string)null })
            {
                if (Outcome(cipher, "EncryptStringAES", invalid, secret) != Outcome(target, "EncryptStringAES", invalid, secret) ||
                    Outcome(cipher, "EncryptStringAES", "text", invalid) != Outcome(target, "EncryptStringAES", "text", invalid))
                    throw new Exception("Cipher argument validation changed.");
                checks += 2;
            }
        }
        Console.WriteLine("PASS: actual license cipher protected; cross-decryption and invalid-input behavior preserved.");
        return checks;
    }
}
