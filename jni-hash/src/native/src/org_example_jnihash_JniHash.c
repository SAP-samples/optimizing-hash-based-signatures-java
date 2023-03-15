#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../include/org_example_jnihash_JniHash.h"
#include "sha256.h"

#define DIGEST_OUTUT_LENGTH SHA256_DIGEST_LENGTH

JNIEXPORT void JNICALL Java_org_example_jnihash_JniHash_sha2_1unsafe(JNIEnv *env, jobject obj, jlong inBufAddress, jint inLength, jlong outBufAddress)
{
    unsigned char *inBuf = (unsigned char *)inBufAddress;
    unsigned char *outBuf = (unsigned char *)outBufAddress;

    sha2_256_custom_padding_no_copy(inBuf, inLength, outBuf);
}

JNIEXPORT void JNICALL Java_org_example_jnihash_JniHash_sha2_1unsafe_1fixed_1padding(JNIEnv *env, jobject obj, jlong inBufAddress, jint fixedSizeIndex, jlong outBufAddress)
{
    unsigned char *inBuf = (unsigned char *)inBufAddress;
    unsigned char *outBuf = (unsigned char *)outBufAddress;

    sha2_256_length(fixedSizeIndex, inBuf, outBuf);
}

JNIEXPORT jbyteArray JNICALL Java_org_example_jnihash_JniHash_sha2_1context(JNIEnv *env, jobject obj)
{
    SHA256_CTX native_context;

    SHA256_Init(&native_context);

    jbyteArray context = (*env)->NewByteArray(env, sizeof(SHA256_CTX));

    (*env)->SetByteArrayRegion(env, context, 0, sizeof(SHA256_CTX), (const jbyte *)&native_context);
    return context;
}

JNIEXPORT void JNICALL Java_org_example_jnihash_JniHash_sha2_1update(JNIEnv *env, jobject obj, jbyteArray context, jbyteArray data, jint inOff, jint len)
{
    jbyte native_data[len];
    (*env)->GetByteArrayRegion(env, data, inOff, len, native_data);

    SHA256_CTX native_context;
    (*env)->GetByteArrayRegion(env, context, 0, sizeof(SHA256_CTX), (jbyte *)&native_context);

    SHA256_Update(&native_context, native_data, len);

    (*env)->SetByteArrayRegion(env, context, 0, sizeof(SHA256_CTX), (const jbyte *)&native_context);
}

JNIEXPORT jint JNICALL Java_org_example_jnihash_JniHash_sha2_1256_1doFinal(JNIEnv *env, jobject obj, jbyteArray context, jbyteArray out, jint outOff)
{
    SHA256_CTX native_context;
    (*env)->GetByteArrayRegion(env, context, 0, sizeof(SHA256_CTX), (jbyte *)&native_context);

    char native_md[SHA256_DIGEST_LENGTH];
    jint r = SHA256_Final(native_md, &native_context);

    (*env)->SetByteArrayRegion(env, out, outOff, SHA256_DIGEST_LENGTH, native_md);

    // TODO: Do we need to update the Java digest context? Or trigger reset (lazily) from Java?

    return r;
}

JNIEXPORT jlong JNICALL Java_org_example_jnihash_JniHash_sha2_1intermediate_1state(JNIEnv *env, jobject obj, jlong inBufAddress, jint inLength)
{

    SHA256_CTX *ctx = malloc(sizeof(SHA256_CTX));
    SHA256_Init(ctx);

    SHA256_Update(ctx, (void *)inBufAddress, inLength);

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_example_jnihash_JniHash_sha2_1256_1768_1lastBlock(JNIEnv *env, jobject obj, jlong ctxAddress, jlong inBufAddress, jlong outBufAddress)
{
    SHA256_CTX local_ctx;
    memcpy(&local_ctx, (void *)ctxAddress, sizeof(SHA256_CTX));

    unsigned char *inBuf = (unsigned char *)inBufAddress;
    unsigned char *outBuf = (unsigned char *)outBufAddress;

    SHA256_Update(&local_ctx, inBuf, 32);
    SHA256_Update(&local_ctx, pad_sha2_256_768, 32);

    hash_make_string(&local_ctx, outBuf);
}

JNIEXPORT void JNICALL Java_org_example_jnihash_JniHash_sha2_1free_1state(JNIEnv *env, jclass clazz, jlong ctx)
{
    free((void *)ctx);
}
