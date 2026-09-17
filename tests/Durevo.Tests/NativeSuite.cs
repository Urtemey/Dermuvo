using Durevo.Runtime;
using O = Durevo.Runtime.IntegerMachine.Operation;

internal static class NativeSuite
{
    internal static int Run()
    {
        int count = 0;
        int[] Encode(int[] code, int key) => code.Select((v,i) => v ^ unchecked(key+i*(int)0x9e3779b9)).ToArray();
        object Invoke(bool native, int[] code, int[] args, int key)
        {
            try { return native ? NativeIntegerMachine.RunWithBudget(code,args,2,8,key,10000)
                : IntegerMachine.Run(code,args,2,8,key); }
            catch(Exception e) { return e.GetType().FullName!; }
        }
        var values = new[] {int.MinValue,int.MaxValue,-239,-32,-1,0,1,31,32,239};
        foreach(var op in Enum.GetValues<O>())
        {
            bool binary = op is >= O.Add and <= O.ShrUnsigned || op is >= O.Equal and <= O.LessUnsigned ||
                op is >= O.AddChecked and <= O.MulCheckedUnsigned;
            bool branch = op is >= O.Eq and <= O.LtUnsigned;
            if(!binary && !branch) continue;
            foreach(int a in values) foreach(int b in values)
            {
                int key = unchecked(a*7919+b);
                int[] raw = branch
                    ? [(int)O.Argument,0,(int)O.Argument,1,(int)op,10,(int)O.Constant,0,(int)O.Return,0,(int)O.Constant,1,(int)O.Return,0]
                    : [(int)O.Argument,0,(int)O.Argument,1,(int)op,0,(int)O.Return,0];
                var code=Encode(raw,key);
                var actual=Invoke(true,code,[a,b],key); var expected=Invoke(false,code,[a,b],key);
                if(!Equals(actual,expected)) throw new Exception($"Native {op}({a},{b}): {actual} != {expected}");
                count++;
            }
        }
        foreach(int a in values) foreach(var op in new[]{O.Neg,O.Not})
        {
            var code=Encode([(int)O.Argument,0,(int)op,0,(int)O.Return,0],123);
            if(!Equals(Invoke(true,code,[a],123),Invoke(false,code,[a],123))) throw new Exception("Native unary mismatch");
            count++;
        }
        void Reject(int[] raw, string expected)
        {
            object actual = Invoke(true,Encode(raw,456),[],456);
            if(!Equals(actual,expected)) throw new Exception($"Malformed native program returned {actual}");
            count++;
        }
        const string invalid = "System.InvalidOperationException";
        Reject([],invalid); Reject([0],invalid); Reject([999,0],invalid);
        Reject([(int)O.Return,0],invalid);
        Reject([(int)O.Add,0,(int)O.Return,0],invalid);
        Reject([(int)O.Argument,0,(int)O.Return,0],invalid);
        Reject([(int)O.LoadLocal,2,(int)O.Return,0],invalid);
        Reject([(int)O.Constant,1,(int)O.StoreLocal,2,(int)O.Return,0],invalid);
        Reject([(int)O.Jump,1],invalid); Reject([(int)O.Jump,2],invalid);
        Reject([(int)O.Jump,0],"System.TimeoutException");
        Reject(Enumerable.Range(0,9).SelectMany(_=>new[]{(int)O.Constant,1}).Concat(new[]{(int)O.Return,0}).ToArray(),invalid);
        Console.WriteLine($"Native suite: {count} differential/boundary checks passed.");
        return count;
    }
}
