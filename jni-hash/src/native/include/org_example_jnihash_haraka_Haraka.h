/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_example_jnihash_haraka_Haraka */

#ifndef _Included_org_example_jnihash_haraka_Haraka
#define _Included_org_example_jnihash_haraka_Haraka
#ifdef __cplusplus
extern "C" {
#endif
#undef org_example_jnihash_haraka_Haraka_ROUNDS
#define org_example_jnihash_haraka_Haraka_ROUNDS 5L
#undef org_example_jnihash_haraka_Haraka_AES_ROUNDS
#define org_example_jnihash_haraka_Haraka_AES_ROUNDS 2L
/*
 * Class:     org_example_jnihash_haraka_Haraka
 * Method:    haraka256
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_example_jnihash_haraka_Haraka_haraka256
  (JNIEnv *, jobject, jlong);

/*
 * Class:     org_example_jnihash_haraka_Haraka
 * Method:    haraka512
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_example_jnihash_haraka_Haraka_haraka512
  (JNIEnv *, jobject, jlong);

/*
 * Class:     org_example_jnihash_haraka_Haraka
 * Method:    haraka512perm
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_example_jnihash_haraka_Haraka_haraka512perm
  (JNIEnv *, jobject, jlong);

/*
 * Class:     org_example_jnihash_haraka_Haraka
 * Method:    load_constants
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_example_jnihash_haraka_Haraka_load_1constants
  (JNIEnv *, jobject);

/*
 * Class:     org_example_jnihash_haraka_Haraka
 * Method:    set_constants
 * Signature: ([I)V
 */
JNIEXPORT void JNICALL Java_org_example_jnihash_haraka_Haraka_set_1constants
  (JNIEnv *, jobject, jintArray);

/*
 * Class:     org_example_jnihash_haraka_Haraka
 * Method:    check_for_native_instructions
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_example_jnihash_haraka_Haraka_check_1for_1native_1instructions
  (JNIEnv *, jclass);

#ifdef __cplusplus
}
#endif
#endif