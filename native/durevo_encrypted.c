/* Builds the existing VM plus authenticated native execution in one translation unit. */
#include "durevo_vm.c"
#if defined(_WIN32)
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:5105) /* Windows SDK 10.0.19041 header macro only. */
#endif
#include <windows.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#else
#include <openssl/evp.h>
#endif

enum { EVM_AUTH = 6, EVM_CRYPTO = 7 };
typedef struct { unsigned char bytes[32]; } durevo_key;
static void evm_wipe(void *memory, size_t length) {
    volatile unsigned char *p = (volatile unsigned char *)memory;
    while (length--) *p++ = 0;
}
static uint32_t evm_le32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
/* Caller must keep opaque handle alive for each call; SafeHandle enforces this for .NET. */
EXPORT int durevo_key_create(const unsigned char *key, uint32_t length, void **out_key) {
    if (!out_key) return INVALID;
    *out_key = NULL;
    if (!key || length != 32) return INVALID;
    durevo_key *owned = malloc(sizeof(*owned));
    if (!owned) return ALLOCATION;
    memcpy(owned->bytes, key, 32);
    *out_key = owned;
    return OK;
}
EXPORT void durevo_key_destroy(void *handle) {
    if (handle) { evm_wipe(handle, sizeof(durevo_key)); free(handle); }
}
static int evm_decrypt(const durevo_key *key, const unsigned char *nonce,
    const unsigned char *ciphertext, uint32_t count, const unsigned char *tag,
    const unsigned char *aad, uint32_t aad_length, unsigned char *plain) {
#if defined(_WIN32)
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE aes_key = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    ULONG written = 0;
    NTSTATUS status;
    int answer = EVM_CRYPTO;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) goto done;
    if (BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) goto done;
    if (BCryptGenerateSymmetricKey(algorithm, &aes_key, NULL, 0, (PUCHAR)key->bytes, 32, 0) < 0) goto done;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce; info.cbNonce = 12;
    info.pbTag = (PUCHAR)tag; info.cbTag = 16;
    info.pbAuthData = (PUCHAR)aad; info.cbAuthData = aad_length;
    status = BCryptDecrypt(aes_key, (PUCHAR)ciphertext, count, &info, NULL, 0, plain, count, &written, 0);
    if (status >= 0 && written == count) answer = OK;
    else if ((uint32_t)status == UINT32_C(0xc000a002)) answer = EVM_AUTH;
done:
    if (aes_key) BCryptDestroyKey(aes_key);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return answer;
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int length = 0, written = 0, tail = 0, answer = EVM_CRYPTO;
    if (!ctx) return ALLOCATION;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key->bytes, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &length, aad, (int)aad_length) != 1 ||
        EVP_DecryptUpdate(ctx, plain, &written, ciphertext, (int)count) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, plain + written, &tail) != 1) { answer = EVM_AUTH; goto done; }
    if (written + tail == (int)count) answer = OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return answer;
#endif
}
static int durevo_run_encrypted_core(const void *handle, const unsigned char *envelope, uint32_t envelope_length,
    const unsigned char *aad, uint32_t aad_length, const int32_t *arguments, uint32_t argc,
    uint64_t steps, int32_t *result, const vm_strings *strings) {
    if (!result) return INVALID;
    *result = 0;
    if (!strings_valid(strings) || !handle || !envelope || envelope_length < 68 || envelope_length > 36 + 24 + 262144 * 4 ||
        !aad || aad_length < 45 || aad_length > 4140 || (argc && !arguments) || argc > 65536 ||
        memcmp(envelope, "DUR-EVM1", 8) != 0 ||
        memcmp(aad, "DUR-EVM1", 8) != 0 || evm_le32(aad + 40) != aad_length - 44) return INVALID;
    uint32_t plain_length = envelope_length - 36;
    unsigned char *plain = malloc((size_t)plain_length + 16);
    uint32_t *program = NULL, words = 0;
    if (!plain) return ALLOCATION;
    int answer = evm_decrypt((const durevo_key *)handle, envelope + 8, envelope + 20, plain_length,
        envelope + envelope_length - 16, aad, aad_length, plain);
    if (answer != OK) goto done;
    /* No metadata or instructions are interpreted before authentication succeeds. */
    uint32_t backend = evm_le32(plain), locals = evm_le32(plain + 4), stack = evm_le32(plain + 8);
    uint32_t expected_args = evm_le32(plain + 12), mask = evm_le32(plain + 16);
    words = evm_le32(plain + 20);
    answer = INVALID;
    if (backend != 1 || locals > 65536 || stack < 1 || stack > 65536 || expected_args != argc ||
        words < 2 || words > 262144 || (words & 1) || plain_length != 24 + words * 4) goto done;
    program = malloc((size_t)words * sizeof(uint32_t));
    if (!program) { answer = ALLOCATION; goto done; }
    for (uint32_t i = 0; i < words; ++i) program[i] = evm_le32(plain + 24 + i * 4);
    answer = durevo_run_core(program, words, arguments, argc, locals, stack, mask, steps, result, strings);
done:
    if (program) { evm_wipe(program, (size_t)words * sizeof(uint32_t)); free(program); }
    evm_wipe(plain, (size_t)plain_length + 16); free(plain);
    return answer;
}

EXPORT int durevo_run_encrypted(const void *handle, const unsigned char *envelope, uint32_t envelope_length,
    const unsigned char *aad, uint32_t aad_length, const int32_t *arguments, uint32_t argc,
    uint64_t steps, int32_t *result) {
    return durevo_run_encrypted_core(handle, envelope, envelope_length, aad, aad_length, arguments, argc, steps, result, NULL);
}
EXPORT int durevo_run_encrypted_strings(const void *handle, const unsigned char *envelope, uint32_t envelope_length,
    const unsigned char *aad, uint32_t aad_length, const int32_t *arguments, uint32_t argc,
    const uint16_t *const *values, const int32_t *lengths, uint32_t string_count, uint64_t steps, int32_t *result) {
    vm_strings strings = { values, lengths, string_count };
    return durevo_run_encrypted_core(handle, envelope, envelope_length, aad, aad_length, arguments, argc, steps, result, &strings);
}
