#include <assert.h>
#include <stdio.h>
#include "durevo_vm.c"
static uint32_t state = 0x7ad399;
static uint32_t next_word(void) { state ^= state << 13; state ^= state >> 17; state ^= state << 5; return state; }
int main(void) {
    uint16_t text[] = {0, 0xd800, 0xdfff, '(', ')', ',', 0xffff, 'a'};
    const uint16_t *texts[] = {text, NULL, NULL};
    int32_t lengths[] = {8, -1, 0}, args[] = {0,1,2,-1};
    uint32_t program[64];
    int32_t result = 0;
    for (int n = 0; n < 100000; ++n) {
        uint32_t count = 2 * (1 + next_word() % 32), key = next_word();
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t value = (i & 1) ? next_word() % 70 : next_word() % (OP_StoreBoolLocal + 1);
            program[i] = value ^ (key + i * UINT32_C(0x9e3779b9));
        }
        int status = durevo_run_strings(program,count,args,4,4,8,key,texts,lengths,3,100,&result);
        assert((status >= OK && status <= BUDGET) || status == 8 || status == 9);
        if (status != OK) assert(result == 0);
    }
    uint32_t length_code[] = {OP_Argument,0,OP_StringLength,0,OP_Return,0};
    for (uint32_t i = 0; i < 6; ++i) length_code[i] ^= i * UINT32_C(0x9e3779b9);
    args[0] = 1;
    assert(durevo_run_strings(length_code,6,args,1,0,1,0,texts,lengths,3,100,&result) == OK && result == 8);
    args[0] = 0;
    assert(durevo_run_strings(length_code,6,args,1,0,1,0,texts,lengths,3,100,&result) == 8 && result == 0);
    args[0] = 3;
    assert(durevo_run_strings(length_code,6,args,1,0,1,0,texts,lengths,3,100,&result) == OK && result == 0);
    lengths[1] = -2;
    assert(durevo_run_strings(length_code,6,args,1,0,1,0,texts,lengths,3,100,&result) == INVALID);
    puts("PASS: 100000 malformed string/scalar programs under sanitizers.");
    return 0;
}
