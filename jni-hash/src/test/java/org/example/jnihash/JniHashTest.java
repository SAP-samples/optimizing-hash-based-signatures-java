package org.example.jnihash;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.function.BiConsumer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;



public class JniHashTest {
    @FunctionalInterface
    interface XmssHash {
        void xmssHash(int fixedValue, byte[] key, byte[] index, byte[] out);
    }
    static void assertFirst24BytesEqual(byte[] a, byte[] b) {
        for (int i = 0; i < 24; i++) {
            assertEquals(a[i], b[i]);
        }
    }

    private static void u32str(int n, Digest d) {
        d.update((byte) (n >>> 24));
        d.update((byte) (n >>> 16));
        d.update((byte) (n >>> 8));
        d.update((byte) (n));
    }

    private static void u16str(short n, Digest d) {
        d.update((byte) (n >>> 8));
        d.update((byte) (n));
    }

    private void test_hash_length(int length, int digestLength, BiConsumer<byte[], byte[]> hash) {
        byte[] data = new byte[length];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }

        byte[] jni_length_md = new byte[32];
        hash.accept(data, jni_length_md);

        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        messageDigest.update(data);
        byte[] direct_md = messageDigest.digest();

        if (digestLength == 24) {
            assertFirst24BytesEqual(direct_md, jni_length_md);
        } else {
            assertArrayEquals(direct_md, jni_length_md);
        }
    }

    private void test_hash_length_xmss(int paddingLength, int keyLength, int indexLength, int digestLength, XmssHash hash) {
        byte[] data = new byte[paddingLength + keyLength + indexLength];
        data[paddingLength - 1] = 42;

        byte[] jni_length_md = new byte[32];
        hash.xmssHash(42, new byte[32], new byte[64], jni_length_md);

        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        messageDigest.update(data);
        byte[] direct_md = messageDigest.digest();

        if (digestLength == 24) {
            assertFirst24BytesEqual(direct_md, jni_length_md);
        } else {
            assertArrayEquals(direct_md, jni_length_md);
        }

    }

    @Test
    public void test_lms_sha2_256() {
        short D_LEAF = (short) 0x8282;
        short D_INTR = (short) 0x8383;

        JniHash h = new JniHash();

        byte[] I = new byte[16];
        I[3] = 0x42;
        int r = 0x1337;
        byte[] d1 = new byte[32];
        d1[11] = 0x20;
        byte[] d2 = new byte[32];
        d2[7] = 0x13;


        // Test tree leaf

        byte[] jni_lms_hash = new byte[32];
        h.sha2_lms_tree_leaf(I, r, d1, jni_lms_hash);

        byte[] direct_hash = new byte[32];
        Digest d = new SHA256Digest();
        d.update(I, 0, I.length);
        u32str(r, d);
        u16str(D_LEAF, d);
        d.update(d1, 0, d1.length);
        d.doFinal(direct_hash, 0);

        assertArrayEquals(direct_hash, jni_lms_hash);

        // Test tree intermediate

        h.sha2_lms_tree_intermediate(I, r, d1, d2, jni_lms_hash);

        d = new SHA256Digest();
        d.update(I, 0, I.length);
        u32str(r, d);
        u16str(D_INTR, d);
        d.update(d1, 0, d1.length);
        d.update(d2, 0, d2.length);
        d.doFinal(direct_hash, 0);

        assertArrayEquals(direct_hash, jni_lms_hash);

        // Test chaining
        h.sha2_lms_ots_chain(I, 1337, 42, 3, d1, jni_lms_hash);

        d = new SHA256Digest();
        d.update(I, 0, I.length);
        u32str(1337, d);
        u16str((short) 42, d);
        d.update((byte) 3);
        d.update(d1, 0, d1.length);
        d.doFinal(direct_hash, 0);

        assertArrayEquals(direct_hash, jni_lms_hash);
    }

    @Test
    public void test_lms_sha2_192() {
        short D_LEAF = (short) 0x8282;
        short D_INTR = (short) 0x8383;

        JniHash h = new JniHash();

        byte[] I = new byte[16];
        I[3] = 0x42;
        int r = 0x1337;
        byte[] d1 = new byte[24];
        d1[11] = 0x20;
        byte[] d2 = new byte[24];
        d2[7] = 0x13;


        // Test tree leaf

        byte[] jni_lms_hash = new byte[24];
        h.sha2_lms_tree_leaf(I, r, d1, jni_lms_hash);

        byte[] direct_hash = new byte[32];
        Digest d = new SHA256Digest();
        d.update(I, 0, I.length);
        u32str(r, d);
        u16str(D_LEAF, d);
        d.update(d1, 0, d1.length);
        d.doFinal(direct_hash, 0);

        assertFirst24BytesEqual(direct_hash, jni_lms_hash);

        // Test tree intermediate

        h.sha2_lms_tree_intermediate(I, r, d1, d2, jni_lms_hash);

        d = new SHA256Digest();
        d.update(I, 0, I.length);
        u32str(r, d);
        u16str(D_INTR, d);
        d.update(d1, 0, d1.length);
        d.update(d2, 0, d2.length);
        d.doFinal(direct_hash, 0);

        assertFirst24BytesEqual(direct_hash, jni_lms_hash);

        // Test chaining
        h.sha2_lms_ots_chain(I, 1337, 42, 3, d1, jni_lms_hash);

        d = new SHA256Digest();
        d.update(I, 0, I.length);
        u32str(1337, d);
        u16str((short) 42, d);
        d.update((byte) 3);
        d.update(d1, 0, d1.length);
        d.doFinal(direct_hash, 0);

        assertFirst24BytesEqual(direct_hash, jni_lms_hash);
    }


    @Test
    public void test_Digest() {
        byte[] data = new byte[1024];
        data[1000] = 0x42;

        JniSha256Digest d = new JniSha256Digest();

        d.update(data, 0, 1024);
        byte[] digest_hash_1 = new byte[32];
        d.doFinal(digest_hash_1, 0);

        d.reset();
        d.update(data, 0, 512);
        d.update(data, 512, 512);
        byte[] digest_hash_2 = new byte[32];
        d.doFinal(digest_hash_2, 0);

        assertArrayEquals(digest_hash_1, digest_hash_2);
    }
}
