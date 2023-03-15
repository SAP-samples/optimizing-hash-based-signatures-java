#include "../include/org_example_jnihash_JniShake.h"
#include <openssl/evp.h>
#include "sha256.h"
#include "SimpleFIPS202.h"
#include "KeccakHash.h"

JNIEXPORT void JNICALL Java_org_example_jnihash_JniShake_shake256_1unsafe(JNIEnv *env, jobject obj, jlong inBufAddress, jint inputSize, jlong outBufAddress, jint digestSize)
{
    char *inBuf = (char *)inBufAddress;
    char *outBuf = (char *)outBufAddress;
    SHAKE256(outBuf, digestSize, inBuf, inputSize);
}

JNIEXPORT jlong JNICALL Java_org_example_jnihash_JniShake_shake256_1context(JNIEnv *env, jobject obj)
{
    Keccak_HashInstance *ctx = malloc(sizeof(Keccak_HashInstance));
    Keccak_HashInitialize_SHAKE256(ctx);
    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_example_jnihash_JniShake_shake256_1free(JNIEnv *env, jobject obj, jlong ctx)
{
    free((void *)ctx);
}

JNIEXPORT void JNICALL Java_org_example_jnihash_JniShake_shake256_1update(JNIEnv *env, jobject obj, jlong ctx, jbyteArray data, jint inOff, jint length)
{
    char native_data[length];
    (*env)->GetByteArrayRegion(env, data, inOff, length, native_data);

    Keccak_HashUpdate((Keccak_HashInstance *)ctx, native_data, length * 8);
}

JNIEXPORT void JNICALL Java_org_example_jnihash_JniShake_shake256_1doFinal(JNIEnv *env, jobject obj, jlong ctx, jint digestLength, jbyteArray out, jint outOff)
{
    char native_md[digestLength];

    Keccak_HashFinal((Keccak_HashInstance *)ctx, NULL);
    Keccak_HashSqueeze((Keccak_HashInstance *)ctx, native_md, digestLength * 8);
    Keccak_HashInitialize_SHAKE256((Keccak_HashInstance *)ctx);

    (*env)->SetByteArrayRegion(env, out, outOff, digestLength, native_md);
}

char *pk_seed = NULL;
int n = -1;
jboolean robust = 1;

static void bitmask(char *adrs, char *m, int m_len)
{
    int hash_in_size = n + 32;
    char hash_in[hash_in_size];
    char mask[m_len];

    memcpy(hash_in, pk_seed, n);
    memcpy(hash_in + n, adrs, 32);

    SHAKE256(mask, m_len, hash_in, hash_in_size);

    for (int i = 0; i < m_len; i++)
    {
        m[i] ^= mask[i];
    }
}

JNIEXPORT void JNICALL Java_org_example_jnihash_JniShake_shake256_1sphincs_1init_1native(JNIEnv *env, jobject obj, jbyteArray _pk_seed, jint _n, jboolean _robust)
{
    n = _n;
    robust = _robust;
    pk_seed = (*env)->GetByteArrayElements(env, _pk_seed, NULL);
}

JNIEXPORT void JNICALL Java_org_example_jnihash_JniShake_shake256_1unsafe_1with_1seed(JNIEnv *env, jobject obj, jlong inAddress, jint inSize, jlong outAddress, jint outSize)
{
    char *in = (char *)inAddress;
    char *out = (char *)outAddress;

    memcpy(in, pk_seed, n);


    SHAKE256(out, outSize, in, inSize);
}

JNIEXPORT void JNICALL Java_org_example_jnihash_JniShake_shake256_1unsafe_1with_1seed_1robust(JNIEnv *env, jobject obj, jlong inAddress, jint inSize, jlong outAddress, jint outSize)
{
    char *in = (char *)inAddress;
    char *out = (char *)outAddress;

    memcpy(in, pk_seed, n);

    bitmask(in + n, in + n + 32, inSize - 32 - n);

    SHAKE256(out, outSize, in, inSize);
}