package org.example.bcpqc.pqc.crypto.xmss;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.encoders.Hex;
import org.example.bcpqc.experiments.hashing.*;
import org.example.bcpqc.pqc.crypto.xmss.khf.KeyedHashFunctions;
import sun.security.provider.SHAKE256;

public class XMSSHashTest extends TestCase {
    private void test_sha256(KeyedHashFunctions khf) {

        // F
        {
            byte[] key = new byte[32];
            byte[] in = new byte[32];
            byte[] result = khf.F(key, in);
            String expected = "2ea9ab9198d1638007400cd2c3bef1cc745b864b76011a0e1bc52180ac6452d4";
            assertEquals(expected, Hex.toHexString(result));
        }
        // H
        {
            byte[] key = new byte[32];
            byte[] in = new byte[64];
            byte[] result = khf.H(key, in);
            String expected = "0175167f2ff4aed5eab5d4048be31b579fa14d3a289bd01e48aab0570309b36b";
            assertEquals(expected, Hex.toHexString(result));
        }

        // HMsg
        {
            byte[] key = new byte[96];
            byte[] in = new byte[1337];
            byte[] result = khf.HMsg(key, in);
            String expected = "9330e1a3b1333a958611f72fc285a73bb620e2c82acdea154470657b8f40332a";
            assertEquals(expected, Hex.toHexString(result));
        }

        // PRF (repeat to test caching)
        {
            byte[] key = new byte[32];
            byte[] in = new byte[32];
            byte[] result = khf.PRF(key, in);
            String expected = "6945a6f13aa83e598cb8d0abebb5cddbd87e576226517f9001c1d36bb320bf80";
            assertEquals(expected, Hex.toHexString(result));

            // Test second run with precalculated first block
            result = khf.PRF(key, in);
            assertEquals(expected, Hex.toHexString(result));
        }
    }

    public void test_sha256_bc() {
        KeyedHashFunctions khf = (new BCHashingProvider()).newKHF(NISTObjectIdentifiers.id_sha256, 32);
        this.test_sha256(khf);
    }

    public void test_sha256_bc_optimized() {
        KeyedHashFunctions khf = (new BCOptimizedHashingProvider()).newKHF(NISTObjectIdentifiers.id_sha256, 32);
        this.test_sha256(khf);
    }

    public void test_sha256_java() {
        KeyedHashFunctions khf = (new JavaHashingProvider()).newKHF(NISTObjectIdentifiers.id_sha256, 32);
        this.test_sha256(khf);
    }

    public void test_sha256_java_optimized() {
        KeyedHashFunctions khf = (new JavaOptimizedHashingProvider()).newKHF(NISTObjectIdentifiers.id_sha256, 32);
        this.test_sha256(khf);
    }


    public void test_sha256_corretto() {
        KeyedHashFunctions khf = (new CorrettoHashingProvider()).newKHF(NISTObjectIdentifiers.id_sha256, 32);
        this.test_sha256(khf);
    }

    public void test_sha256_jni() {
        KeyedHashFunctions khf = (new JNIHashingProvider()).newKHF(NISTObjectIdentifiers.id_sha256, 32);
        this.test_sha256(khf);
    }

    public void test_sha256_jni_fixed_padding() {
        KeyedHashFunctions khf = (new JNIFixedPaddingHashingProvider()).newKHF(NISTObjectIdentifiers.id_sha256, 32);
        this.test_sha256(khf);
    }

    public void test_sha256_jni_prf_caching() {
        KeyedHashFunctions khf = (new JNIPrfCachingHashingProvider()).newKHF(NISTObjectIdentifiers.id_sha256, 32);
        this.test_sha256(khf);
    }

    public void test_bc_java_optimized() {
        KeyedHashFunctions bc = (new BCHashingProvider()).newKHF(NISTObjectIdentifiers.id_sha256, 32);
        KeyedHashFunctions javaOptimized = (new JavaOptimizedHashingProvider()).newKHF(NISTObjectIdentifiers.id_sha256, 32);

        for (int i = 0; i < 128; i++) {
            // F & PRF
            {
                byte[] key = new byte[32];
                key[i % 32] = (byte) (i % 25);
                key[1] = 7;
                key[0] = (byte) i;
                byte[] in = new byte[32];
                in[1] = (byte) (i + 42);
                assertBytesEquals(bc.F(key, in), javaOptimized.F(key, in));
                assertBytesEquals(bc.F(key, in), javaOptimized.F(key, in));
                assertBytesEquals(bc.F(key, in), javaOptimized.F(key, in));


                // Run multiple times to test caching
                assertBytesEquals(bc.PRF(key, in), javaOptimized.PRF(key, in));
                assertBytesEquals(bc.PRF(key, in), javaOptimized.PRF(key, in));
                assertBytesEquals(bc.PRF(key, in), javaOptimized.PRF(key, in));
            }
            // HMsg
            {
                byte[] key = new byte[96];
                byte[] in = new byte[1337];
                key[2] = (byte) i;
                key[42] = 101;
                in[i] = 13;
                in[i * 3] = 13;
                in[421] = 37;
                assertBytesEquals(bc.HMsg(key, in), javaOptimized.HMsg(key, in));
                assertBytesEquals(bc.HMsg(key, in), javaOptimized.HMsg(key, in));

            }
            // H
            {
                byte[] key = new byte[32];
                key[(i + 13) % 32] = 37;
                byte[] in = new byte[64];
                in[37] = 13;
                assertBytesEquals(bc.H(key, in), javaOptimized.H(key, in));
                assertBytesEquals(bc.H(key, in), javaOptimized.H(key, in));

            }
            {
                byte[] key = new byte[32];
                key[(i + 1) % 20 + 1] = (byte) i;
                key[1] = 0;
                key[0] = (byte) i;

                byte[] in = new byte[32];
                in[i % 32] = 1;
                assertBytesEquals(bc.F(key, in), javaOptimized.F(key, in));
                assertBytesEquals(bc.F(key, in), javaOptimized.F(key, in));
                assertBytesEquals(bc.F(key, in), javaOptimized.F(key, in));


                // Run multiple times to test caching
                assertBytesEquals(bc.PRF(key, in), javaOptimized.PRF(key, in));
                assertBytesEquals(bc.PRF(key, in), javaOptimized.PRF(key, in));
                assertBytesEquals(bc.PRF(key, in), javaOptimized.PRF(key, in));
            }
        }


    }

    private void assertBytesEquals(byte[] b1, byte[] b2) {
        assertEquals(Hex.toHexString(b1), Hex.toHexString(b2));
    }

    public void testJavaShake256() {
        byte[] data = new byte[42];
        data[13] = 37;

        SHAKE256 shake256 = new SHAKE256(0);
        shake256.engineUpdate(data, 0, data.length);
        byte[] digest_java = new byte[200];
        shake256.digest(digest_java, 0, digest_java.length);

        byte[] digest_bc = new byte[200];
        SHAKEDigest bc_shake = new SHAKEDigest(256);
        bc_shake.update(data, 0, data.length);
        bc_shake.doFinal(digest_bc, 0, digest_bc.length);

        assertEquals(Hex.toHexString(digest_java), Hex.toHexString(digest_bc));

    }
}
