/* Test-only interposer for the synthetic Durevo ABI driver. No files or secrets are persisted. */
#include <stdint.h>
static int calls;
static int captured;
int durevo_probe_calls(void) { return calls; }
int durevo_probe_captured(void) { return captured; }
int durevo_run(const uint32_t *program, uint32_t length, const int32_t *args, uint32_t argc,
    uint32_t locals, uint32_t stack, uint32_t mask, uint64_t steps, int32_t *result) {
    (void)args; (void)argc; (void)locals; (void)stack; (void)steps;
    ++calls;
    if (program && length == 4 &&
        (program[0] ^ mask) == 1 &&
        (program[1] ^ (mask + UINT32_C(0x9e3779b9))) == 73 &&
        (program[2] ^ (mask + 2 * UINT32_C(0x9e3779b9))) == 38)
        ++captured;
    *result = -999;
    return 0;
}
