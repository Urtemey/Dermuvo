#include <assert.h>
#include <stdio.h>
#include "durevo_encrypted.c"
static uint32_t random_state = 0x918bad;
static uint32_t random_word(void) {
    random_state ^= random_state << 13; random_state ^= random_state >> 17;
    random_state ^= random_state << 5; return random_state;
}
static void put32(unsigned char *p, uint32_t value) {
    for (int i = 0; i < 4; ++i) p[i] = (unsigned char)(value >> (i * 8));
}
int main(void) {
    unsigned char key[32] = {0}, aad[45] = {0};
    void *handle = NULL;
    memcpy(aad, "DUR-EVM1", 8); put32(aad + 40, 1); aad[44] = 'x';
    assert(durevo_key_create(key, 31, &handle) == INVALID && handle == NULL);
    assert(durevo_key_create(key, 32, &handle) == OK && handle != NULL);
    for (int test = 0; test < 10000; ++test) {
        unsigned char plain[88] = {0}, envelope[124] = {0};
        memcpy(envelope, "DUR-EVM1", 8);
        for (int i = 8; i < 20; ++i) envelope[i] = (unsigned char)random_word();
        put32(plain, 1); put32(plain + 4, random_word() % 8);
        put32(plain + 8, 8); put32(plain + 12, 0); put32(plain + 16, 0); put32(plain + 20, 16);
        for (int i = 0; i < 16; ++i) {
            uint32_t word = (i & 1) ? random_word() % 20 : random_word() % 55;
            put32(plain + 24 + i * 4, word ^ ((uint32_t)i * UINT32_C(0x9e3779b9)));
        }
        if (test % 3 == 0) put32(plain + (random_word() % 6) * 4, random_word());
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int written = 0, tail = 0;
        assert(ctx);
        assert(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, envelope + 8) == 1);
        assert(EVP_EncryptUpdate(ctx, NULL, &written, aad, sizeof(aad)) == 1);
        assert(EVP_EncryptUpdate(ctx, envelope + 20, &written, plain, sizeof(plain)) == 1);
        assert(EVP_EncryptFinal_ex(ctx, envelope + 20 + written, &tail) == 1);
        assert(written + tail == sizeof(plain));
        assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, envelope + 108) == 1);
        EVP_CIPHER_CTX_free(ctx);
        if (test % 3 == 1) envelope[20 + random_word() % 104] ^= 1;
        int32_t result = 99;
        int status = durevo_run_encrypted(handle, envelope, sizeof(envelope), aad, sizeof(aad), NULL, 0, 100, &result);
        assert(status >= OK && status <= EVM_CRYPTO);
        if (test % 3 == 1) assert(status == EVM_AUTH);
        if (status != OK) assert(result == 0);
    }
    durevo_key_destroy(handle);
    puts("PASS: 10000 authenticated/mutated native encrypted programs under sanitizers.");
    return 0;
}
