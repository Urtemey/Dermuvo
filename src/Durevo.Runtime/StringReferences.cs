using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
namespace Durevo.Runtime;

// Zero denotes null; nonzero values denote reference identity within this invocation.
public static class StringReferences
{
    private sealed class IdentityComparer : IEqualityComparer<string>
    {
        public bool Equals(string? left, string? right) => ReferenceEquals(left, right);
        public int GetHashCode(string value) => RuntimeHelpers.GetHashCode(value);
    }
    public static int[] CreateTokens(string[] strings)
    {
        if (strings is null || strings.Length > 65536) throw new ArgumentException("Invalid string table.");
        var tokens = new int[strings.Length];
        var identities = new Dictionary<string,int>(new IdentityComparer());
        for (int i = 0; i < strings.Length; i++)
        {
            string value = strings[i];
            if (value == null) continue;
            if (!identities.TryGetValue(value, out int token))
            {
                token = i + 1; identities.Add(value, token);
            }
            tokens[i] = token;
        }
        return tokens;
    }
}
