/* Isolated synthetic test: detects plaintext VM dispatch through an interposable export. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/evp.h>
extern int durevo_key_create(const unsigned char *, uint32_t, void **);
extern void durevo_key_destroy(void *);
extern int durevo_run_encrypted(const void *, const unsigned char *, uint32_t, const unsigned char *,
    uint32_t, const int32_t *, uint32_t, uint64_t, int32_t *);
extern int durevo_run(const uint32_t *, uint32_t, const int32_t *, uint32_t, uint32_t, uint32_t,
    uint32_t, uint64_t, int32_t *);
static void put32(unsigned char *p, uint32_t value) {
    for (int i = 0; i < 4; ++i) p[i] = (unsigned char)(value >> (8 * i));
}
int main(int argc, char **argv) {
    assert(argc == 2);
    int exposed = strcmp(argv[1], "exposed") == 0;
    assert(exposed || strcmp(argv[1], "closed") == 0);
    unsigned char key[32] = {0}, aad[45] = {0}, envelope[76] = {0}, plain[40] = {0};
    uint32_t program[4] = {1,73,38,0}, mask = 17;
    void *handle = NULL;
    int32_t result = 0;
    int (*calls)(void) = (int (*)(void))dlsym(RTLD_DEFAULT, "durevo_probe_calls");
    int (*captured)(void) = (int (*)(void))dlsym(RTLD_DEFAULT, "durevo_probe_captured");
    assert(calls && captured);
    assert(!dlsym(RTLD_DEFAULT, "durevo_run_core"));
    for (uint32_t i = 0; i < 4; ++i) program[i] ^= mask + i * UINT32_C(0x9e3779b9);
    /* Positive loader control: our interposer must intercept the public legacy entry. */
    assert(durevo_run(program, 4, NULL, 0, 0, 1, mask, 100, &result) == 0);
    assert(result == -999 && calls() == 1 && captured() == 1);
    memcpy(aad, "DUR-EVM1", 8); put32(aad + 40, 1); aad[44] = 'x';
    memcpy(envelope, "DUR-EVM1", 8);
    put32(plain, 1); put32(plain + 8, 1); put32(plain + 16, mask); put32(plain + 20, 4);
    for (int i = 0; i < 4; ++i) put32(plain + 24 + 4 * i, program[i]);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int length = 0, tail = 0;
    assert(ctx);
    assert(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, envelope + 8) == 1);
    assert(EVP_EncryptUpdate(ctx, NULL, &length, aad, sizeof(aad)) == 1);
    assert(EVP_EncryptUpdate(ctx, envelope + 20, &length, plain, sizeof(plain)) == 1);
    assert(EVP_EncryptFinal_ex(ctx, envelope + 20 + length, &tail) == 1);
    assert(length + tail == sizeof(plain));
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, envelope + 60) == 1);
    EVP_CIPHER_CTX_free(ctx);
    assert(durevo_key_create(key, sizeof(key), &handle) == 0);
    assert(durevo_run_encrypted(handle, envelope, sizeof(envelope), aad, sizeof(aad),
        NULL, 0, 100, &result) == 0);
    durevo_key_destroy(handle);
    printf("DISPATCH %s: result=%d, intercepted=%d, decoded=%d\n", argv[1], result, calls(), captured());
    assert(result == (exposed ? -999 : 73));
    assert(calls() == (exposed ? 2 : 1));
    assert(captured() == (exposed ? 2 : 1));
    return 0;
}
