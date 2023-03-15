#include "org_example_JniTransfer.h"

#define INLEN 64
#define OUTLEN 32

#define PROCESS(in, out)                    \
    for (int i = 0; i < OUTLEN; i++)        \
    {                                       \
        out[i] = in[2 * i] + in[2 * 1 + 1]; \
    }

JNIEXPORT void JNICALL Java_org_example_JniTransfer_testByteArrayElements(JNIEnv *env, jobject obj, jbyteArray inArray, jbyteArray outArray)
{
    jbyte *in = (*env)->GetByteArrayElements(env, inArray, NULL);
    jbyte *out = (*env)->GetByteArrayElements(env, outArray, NULL);

    PROCESS(in, out);

    (*env)->ReleaseByteArrayElements(env, inArray, in, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, outArray, out, 0);
}

JNIEXPORT void JNICALL Java_org_example_JniTransfer_testByteArrayCritical(JNIEnv *env, jobject obj, jbyteArray inArray, jbyteArray outArray)
{
    jbyte *in = (*env)->GetPrimitiveArrayCritical(env, inArray, NULL);
    jbyte *out = (*env)->GetPrimitiveArrayCritical(env, outArray, NULL);

    PROCESS(in, out);

    (*env)->ReleasePrimitiveArrayCritical(env, inArray, in, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, outArray, out, 0);
}

JNIEXPORT void JNICALL Java_org_example_JniTransfer_testByteArrayRegion(JNIEnv *env, jobject obj, jbyteArray inArray, jbyteArray outArray)
{
    jbyte in[INLEN];
    jbyte out[OUTLEN];

    (*env)->GetByteArrayRegion(env, inArray, 0, INLEN, in);

    PROCESS(in, out);

    (*env)->SetByteArrayRegion(env, outArray, 0, OUTLEN, out);
}

JNIEXPORT void JNICALL Java_org_example_JniTransfer_testByteBuffer(JNIEnv *env, jobject obj, jobject inBuffer, jobject outBuffer)
{
    jbyte *in = (*env)->GetDirectBufferAddress(env, inBuffer);
    jbyte *out = (*env)->GetDirectBufferAddress(env, outBuffer);

    PROCESS(in, out);
}

JNIEXPORT void JNICALL Java_org_example_JniTransfer_testUnsafe(JNIEnv *env, jobject obj, jlong in_handle, jlong out_handle)
{
    jbyte *in = (jbyte *)in_handle;
    jbyte *out = (jbyte *)out_handle;

    PROCESS(in, out);
}
