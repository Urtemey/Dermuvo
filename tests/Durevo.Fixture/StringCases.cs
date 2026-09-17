namespace Durevo.Fixture;
public static class StringCases
{
    public static int TextLength(string value) => value.Length;
    public static char TextAt(string value, int index) => value[index];
    public static int FindChar(string value, char target) => value.IndexOf(target);
    public static int TwoTexts(string left, int index, string right, char target, bool add)
    {
        char c = left[index];
        bool flag = add;
        return flag ? left.Length + c + right.IndexOf(target) : left.Length - c - right.IndexOf(target);
    }
    public static bool ScalarBool(bool enabled, int value) => enabled && value > 3;
    public static char ScalarChar(int value) => unchecked((char)value);
    public static bool IsMissing(string value) => value == null || value.Length == 0;
    public static bool SameReference(string left, string right) => (object)left == (object)right;
    public static bool UnsupportedText(string value) => value.StartsWith("x");
}
