using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Durevo.Core;

// Unity Mono can reject reordered backward edges carrying stack values even when
// CoreCLR executes them. Only reorder methods whose branch edges have empty stacks.
internal static class PermutationSafety
{
    internal static bool CanReorder(MethodDefinition method)
    {
        if (method.Body.HasExceptionHandlers) return false;
        var code = method.Body.Instructions;
        if (code.Count == 0) return false;
        var depths = new Dictionary<Instruction, int>();
        var pending = new Queue<(Instruction Instruction, int Depth)>();
        pending.Enqueue((code[0], 0));
        while (pending.Count != 0)
        {
            var (instruction, depth) = pending.Dequeue();
            if (depths.TryGetValue(instruction, out int previous))
            {
                if (previous != depth) return false;
                continue;
            }
            depths.Add(instruction, depth);
            int pop = Count(instruction.OpCode.StackBehaviourPop);
            int push = Count(instruction.OpCode.StackBehaviourPush);
            if (instruction.Operand is MethodReference callee &&
                instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj)
            {
                pop = callee.Parameters.Count + (callee.HasThis && instruction.OpCode.Code != Code.Newobj ? 1 : 0);
                push = instruction.OpCode.Code == Code.Newobj || callee.ReturnType.MetadataType != MetadataType.Void ? 1 : 0;
            }
            if (instruction.OpCode.Code == Code.Ret)
                pop = method.ReturnType.MetadataType == MetadataType.Void ? 0 : 1;
            if (pop < 0 || push < 0 || depth < pop) return false;
            depth = depth - pop + push;
            var flow = instruction.OpCode.FlowControl;
            if (flow is FlowControl.Branch or FlowControl.Cond_Branch)
            {
                if (depth != 0) return false;
                if (instruction.Operand is Instruction target) pending.Enqueue((target, depth));
                else if (instruction.Operand is Instruction[] targets)
                    foreach (var item in targets) pending.Enqueue((item, depth));
                else return false;
            }
            if (flow is not (FlowControl.Branch or FlowControl.Return or FlowControl.Throw) && instruction.Next != null)
                pending.Enqueue((instruction.Next, depth));
        }
        // Unreachable instruction regions are not proven safe by this analysis.
        return depths.Count == code.Count;
    }

    static int Count(StackBehaviour behavior) => behavior switch
    {
        StackBehaviour.Pop0 or StackBehaviour.Push0 => 0,
        StackBehaviour.Pop1 or StackBehaviour.Popi or StackBehaviour.Popref or
        StackBehaviour.Push1 or StackBehaviour.Pushi or StackBehaviour.Pushi8 or
        StackBehaviour.Pushr4 or StackBehaviour.Pushr8 or StackBehaviour.Pushref => 1,
        StackBehaviour.Pop1_pop1 or StackBehaviour.Popi_pop1 or StackBehaviour.Popi_popi or
        StackBehaviour.Popi_popi8 or StackBehaviour.Popi_popr4 or StackBehaviour.Popi_popr8 or
        StackBehaviour.Popref_pop1 or StackBehaviour.Popref_popi or StackBehaviour.Push1_push1 => 2,
        StackBehaviour.Popi_popi_popi or StackBehaviour.Popref_popi_popi or
        StackBehaviour.Popref_popi_popi8 or StackBehaviour.Popref_popi_popr4 or
        StackBehaviour.Popref_popi_popr8 or StackBehaviour.Popref_popi_popref => 3,
        _ => -1
    };
}
