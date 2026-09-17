using System;
namespace Durevo.Fixture;
public static class ExceptionCases
{
    public static string Trace = "";
    public static string Nested(int x)
    {
        Trace = "";
        try
        {
            try
            {
                Trace += "T";
                for (int i = 0; i < 8; i++)
                    if (((x >> i) & 1) != 0) Trace += "a"; else Trace += "b";
                if (x % 5 == 0) throw new ArgumentException("argument");
                if (x % 7 == 0) throw new InvalidOperationException("operation");
                if (x % 3 == 0) return "early";
                return (239 / x).ToString();
            }
            catch (ArgumentException) { Trace += "C"; return "caught"; }
            finally { Trace += "F"; }
        }
        finally { Trace += "O"; }
    }
    private static bool Accept(int x)
    {
        Trace += "Q";
        if (x == 4) throw new Exception("filter failure");
        return x == 1;
    }
    public static string Filter(int x)
    {
        Trace = "";
        try
        {
            try { Trace += "T"; throw new ArgumentException("filtered"); }
            finally { Trace += "F"; }
        }
        catch (ArgumentException) when (Accept(x)) { Trace += "A"; return "accepted"; }
        catch (Exception) { Trace += "B"; return "fallback"; }
    }
    public static string Rethrow(int x)
    {
        Trace = "";
        try
        {
            try { throw new ArgumentException("original"); }
            catch { Trace += "C"; if (x == 0) throw; throw new InvalidOperationException("replacement"); }
            finally { Trace += "F"; if (x == 2) throw new NotSupportedException("finally"); }
        }
        catch (ArgumentException) { Trace += "A"; return "original"; }
    }
}
