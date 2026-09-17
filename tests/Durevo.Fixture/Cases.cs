namespace Durevo.Fixture;

public static class Cases
{
    public static int Arithmetic(int x, int y) => unchecked((x * 7919 + y) ^ -123456789);
    public static int Branches(int x)
    {
        int sum = 0;
        for (int i = 0; i < 24; i++) sum = unchecked(sum + ((x & (1 << i)) == 0 ? i * 17 : -i * 31));
        return sum;
    }
    public static string Switch(int x) => x switch
    {
        0 => "Durevo-private-alpha", 1 => "кириллица", 2 => "emoji: 😀", 3 => "",
        4 => "zero\0inside", 5 => "\ud800", 6 => "\udfff", _ => "default"
    };
    public static bool Interned() => ReferenceEquals("Durevo-private-alpha", Switch(0));
    public static long Wide(int x) => (long)x * int.MinValue + int.MaxValue;
    public static int Divide(int x) => 239 / x;
    public static int Checked(int x) => checked(x + int.MaxValue);
    public static int CheckedUnsignedAdd(int a, int b) => unchecked((int)checked(unchecked((uint)a)+unchecked((uint)b)));
    public static int CheckedUnsignedSub(int a, int b) => unchecked((int)checked(unchecked((uint)a)-unchecked((uint)b)));
    public static int CheckedUnsignedMul(int a, int b) => unchecked((int)checked(unchecked((uint)a)*unchecked((uint)b)));
    public static int Unsupported(int x) { try { return 12 / x; } catch { return -1; } }
}
