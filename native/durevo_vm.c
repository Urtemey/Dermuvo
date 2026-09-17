#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif
enum operation { OP_Nop, OP_Constant, OP_Argument, OP_LoadLocal, OP_StoreLocal, OP_Dup, OP_Pop, OP_Add, OP_Sub, OP_Mul, OP_Div, OP_Rem, OP_And, OP_Or, OP_Xor, OP_Shl, OP_Shr, OP_ShrUnsigned, OP_Neg, OP_Not, OP_Equal, OP_Greater, OP_Less, OP_GreaterUnsigned, OP_LessUnsigned, OP_Jump, OP_False, OP_True, OP_Eq, OP_Ne, OP_Ge, OP_Gt, OP_Le, OP_Lt, OP_GeUnsigned, OP_GtUnsigned, OP_LeUnsigned, OP_LtUnsigned, OP_Return, OP_AddChecked, OP_SubChecked, OP_MulChecked, OP_DivUnsigned, OP_RemUnsigned, OP_AddCheckedUnsigned, OP_SubCheckedUnsigned, OP_MulCheckedUnsigned, OP_StringLength, OP_StringChar, OP_StringIndexOfChar, OP_ConvertU2, OP_StoreCharLocal, OP_StoreBoolLocal };
enum status { OK, INVALID, DIV_ZERO, OVERFLOW, ALLOCATION, BUDGET };
typedef struct { const uint16_t *const *values; const int32_t *lengths; uint32_t count; } vm_strings;
static int strings_valid(const vm_strings *strings) {
    if (!strings) return 1;
    if (strings->count > 65536 || (strings->count && (!strings->values || !strings->lengths))) return 0;
    for (uint32_t i = 0; i < strings->count; ++i)
        if (strings->lengths[i] < -1 || (strings->lengths[i] > 0 && !strings->values[i])) return 0;
    return 1;
}
static int32_t signed32(uint32_t v) { int32_t r; memcpy(&r, &v, sizeof(r)); return r; }
static uint32_t decode(const uint32_t *p, uint32_t i, uint32_t key) {
    return p[i] ^ (key + i * UINT32_C(0x9e3779b9));
}
/* Caller owns buffers for the duration. No process-global state or external effects. */
static int durevo_run_core(const uint32_t *program, uint32_t length,
    const int32_t *arguments, uint32_t argc, uint32_t local_count,
    uint32_t stack_size, uint32_t key, uint64_t steps, int32_t *result, const vm_strings *strings)
{
    if (!result) return INVALID;
    *result = 0;
    if (!strings_valid(strings) || !program || length < 2 || length > 2000000 || (length & 1) ||
        (argc && !arguments) || argc > 65536 || local_count > 65536 ||
        stack_size < 1 || stack_size > 65536) return INVALID;
    uint32_t *locals = calloc(local_count ? local_count : 1, sizeof(uint32_t));
    uint32_t *stack = calloc(stack_size, sizeof(uint32_t));
    int status = INVALID;
    uint32_t pc = 0, sp = 0;
    if (!locals || !stack) { status = ALLOCATION; goto done; }
    for (;;) {
        if (!steps) { status = BUDGET; goto done; }
        --steps;
        if (pc >= length || (pc & 1)) goto done;
        uint32_t op = decode(program, pc, key), operand = decode(program, pc + 1, key);
        pc += 2;
        uint32_t ua, ub, value = 0;
        int32_t a, b;
        int64_t wide;
        uint64_t uwide;
        if (op > OP_StoreBoolLocal) goto done;
        /* Validate all branch destinations, including untaken branches. */
        if (op >= OP_Jump && op <= OP_LtUnsigned && (operand >= length || (operand & 1))) goto done;
        switch (op) {
        case OP_Nop: break;
        case OP_Constant:
            if (sp == stack_size) goto done;
            stack[sp++] = operand; break;
        case OP_Argument:
            if (sp == stack_size || operand >= argc) goto done;
            stack[sp++] = (uint32_t)arguments[operand]; break;
        case OP_LoadLocal:
            if (sp == stack_size || operand >= local_count) goto done;
            stack[sp++] = locals[operand]; break;
        case OP_StoreCharLocal:
        case OP_StoreBoolLocal:
        case OP_StoreLocal:
            if (!sp || operand >= local_count) goto done;
            value = stack[--sp];
            locals[operand] = op == OP_StoreCharLocal ? value & 65535u : op == OP_StoreBoolLocal ? value & 255u : value; break;
        case OP_ConvertU2:
            if (!sp) goto done;
            stack[sp-1] &= 65535u; break;
        case OP_StringLength:
        case OP_StringChar:
        case OP_StringIndexOfChar: {
            uint32_t needed = op == OP_StringLength ? 1u : 2u;
            if (sp < needed || !strings) goto done;
            uint32_t text = stack[sp-needed], index = op == OP_StringLength ? 0u : stack[sp-1];
            if (text == 0) { status = 8; goto done; }
            --text;
            if (text >= strings->count) goto done;
            int32_t text_length = strings->lengths[text];
            if (text_length == -1) { status = 8; goto done; }
            if (op == OP_StringLength) value = (uint32_t)text_length;
            else if (op == OP_StringChar) {
                if (index >= (uint32_t)text_length) { status = 9; goto done; }
                value = strings->values[text][index];
            } else {
                value = UINT32_MAX;
                for (uint32_t i = 0; i < (uint32_t)text_length; ++i)
                    if (strings->values[text][i] == (uint16_t)index) { value = i; break; }
            }
            sp -= needed; stack[sp++] = value; break;
        }
        case OP_Dup:
            if (!sp || sp == stack_size) goto done;
            value = stack[sp-1]; stack[sp++] = value; break;
        case OP_Pop: if (!sp) goto done; --sp; break;
        case OP_Neg: if (!sp) goto done; stack[sp-1] = 0u - stack[sp-1]; break;
        case OP_Not: if (!sp) goto done; stack[sp-1] = ~stack[sp-1]; break;
        case OP_Jump: pc = operand; break;
        case OP_False: if (!sp) goto done; if (!stack[--sp]) pc = operand; break;
        case OP_True: if (!sp) goto done; if (stack[--sp]) pc = operand; break;
        case OP_Return:
            if (sp != 1) goto done;
            *result = signed32(stack[0]); status = OK; goto done;
        default:
            if (sp < 2) goto done;
            ub = stack[--sp]; ua = stack[--sp]; a = signed32(ua); b = signed32(ub);
            switch (op) {
            case OP_Add: value = ua + ub; break;
            case OP_Sub: value = ua - ub; break;
            case OP_Mul: value = ua * ub; break;
            case OP_Div: case OP_Rem:
                if (!b) { status = DIV_ZERO; goto done; }
                if (a == INT32_MIN && b == -1) { status = OVERFLOW; goto done; }
                value = (uint32_t)(op == OP_Div ? a/b : a%b); break;
            case OP_DivUnsigned: case OP_RemUnsigned:
                if (!ub) { status = DIV_ZERO; goto done; }
                value = op == OP_DivUnsigned ? ua/ub : ua%ub; break;
            case OP_And: value = ua & ub; break;
            case OP_Or: value = ua | ub; break;
            case OP_Xor: value = ua ^ ub; break;
            case OP_Shl: value = ua << (ub & 31); break;
            case OP_ShrUnsigned: value = ua >> (ub & 31); break;
            case OP_Shr:
                value = ua >> (ub & 31);
                if (a < 0 && (ub & 31)) value |= UINT32_MAX << (32 - (ub & 31));
                break;
            case OP_Equal: value = a == b; break;
            case OP_Greater: value = a > b; break;
            case OP_Less: value = a < b; break;
            case OP_GreaterUnsigned: value = ua > ub; break;
            case OP_LessUnsigned: value = ua < ub; break;
            case OP_Eq: if(a==b) pc=operand; continue;
            case OP_Ne: if(a!=b) pc=operand; continue;
            case OP_Ge: if(a>=b) pc=operand; continue;
            case OP_Gt: if(a>b) pc=operand; continue;
            case OP_Le: if(a<=b) pc=operand; continue;
            case OP_Lt: if(a<b) pc=operand; continue;
            case OP_GeUnsigned: if(ua>=ub) pc=operand; continue;
            case OP_GtUnsigned: if(ua>ub) pc=operand; continue;
            case OP_LeUnsigned: if(ua<=ub) pc=operand; continue;
            case OP_LtUnsigned: if(ua<ub) pc=operand; continue;
            case OP_AddChecked: case OP_SubChecked: case OP_MulChecked:
                wide = op == OP_AddChecked ? (int64_t)a+b :
                       op == OP_SubChecked ? (int64_t)a-b : (int64_t)a*b;
                if (wide < INT32_MIN || wide > INT32_MAX) { status = OVERFLOW; goto done; }
                value = (uint32_t)wide; break;
            case OP_AddCheckedUnsigned: case OP_SubCheckedUnsigned: case OP_MulCheckedUnsigned:
                if (op == OP_SubCheckedUnsigned && ua < ub) { status = OVERFLOW; goto done; }
                uwide = op == OP_AddCheckedUnsigned ? (uint64_t)ua+ub :
                        op == OP_SubCheckedUnsigned ? (uint64_t)ua-ub : (uint64_t)ua*ub;
                if (uwide > UINT32_MAX) { status = OVERFLOW; goto done; }
                value = (uint32_t)uwide; break;
            default: goto done;
            }
            stack[sp++] = value; break;
        }
    }
done:
    if (stack) { volatile uint32_t *p = stack; for (uint32_t i = 0; i < stack_size; ++i) p[i] = 0; }
    if (locals) { volatile uint32_t *p = locals; for (uint32_t i = 0; i < (local_count ? local_count : 1); ++i) p[i] = 0; }
    free(stack); free(locals); return status;
}

/* Preserve the legacy ABI. Encrypted execution calls the internal core directly. */
EXPORT int durevo_run(const uint32_t *program, uint32_t length,
    const int32_t *arguments, uint32_t argc, uint32_t local_count,
    uint32_t stack_size, uint32_t key, uint64_t steps, int32_t *result)
{
    return durevo_run_core(program, length, arguments, argc, local_count, stack_size, key, steps, result, NULL);
}
EXPORT int durevo_run_strings(const uint32_t *program, uint32_t length,
    const int32_t *arguments, uint32_t argc, uint32_t local_count, uint32_t stack_size, uint32_t key,
    const uint16_t *const *values, const int32_t *lengths, uint32_t string_count, uint64_t steps, int32_t *result)
{
    vm_strings strings = { values, lengths, string_count };
    return durevo_run_core(program, length, arguments, argc, local_count, stack_size, key, steps, result, &strings);
}
