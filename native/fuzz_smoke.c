#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "durevo_vm.c"
static uint32_t state = 0x12345678;
static uint32_t next_value(void) { state ^= state << 13; state ^= state >> 17; state ^= state << 5; return state; }
int main(void)
{
    uint32_t program[64]; int32_t args[4] = {INT32_MIN, INT32_MAX, -1, 0}; int32_t result;
    assert(durevo_run(NULL, 2, args, 4, 4, 8, 0, 100, &result) == INVALID);
    assert(durevo_run(program, 2, args, 4, 4, 8, 0, 100, NULL) == INVALID);
    for (int test = 0; test < 100000; ++test) {
        uint32_t count = 2 * (1 + next_value() % 32), key = next_value();
        for (uint32_t i=0; i<count; ++i) {
            uint32_t raw = (i & 1) ? next_value() % 70 : next_value() % 50;
            program[i] = raw ^ (key + i * UINT32_C(0x9e3779b9));
        }
        int status = durevo_run(program, count, args, 4, 4, 8, key, 100, &result);
        assert(status >= OK && status <= BUDGET);
        if (status != OK) assert(result == 0);
    }
    puts("PASS: 100000 bounded malformed native programs under sanitizers.");
    return 0;
}
