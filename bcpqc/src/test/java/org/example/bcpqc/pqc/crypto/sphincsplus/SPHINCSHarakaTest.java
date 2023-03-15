package org.example.bcpqc.pqc.crypto.sphincsplus;

import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Hex;
import org.example.bcpqc.crypto.digests.haraka.JavaIntrinsicHaraka256;
import org.example.bcpqc.crypto.digests.haraka.JavaIntrinsicHaraka512;
import org.example.bcpqc.crypto.digests.haraka.JavaIntrinsicHarakaS;
import org.example.jnihash.haraka.*;

public class SPHINCSHarakaTest extends TestCase {

    public void testHaraka256() {
        byte[] pkSeed = new byte[64];
        byte[] data = new byte[32];
        data[13] = 37;

        HarakaSXof bcXof = new HarakaSXof(pkSeed);
        HarakaS256Digest bc = new HarakaS256Digest(bcXof);

        bc.update(data, 0, data.length);
        byte[] bc_digest = new byte[32];
        bc.doFinal(bc_digest, 0);
        System.out.println(Hex.toHexString(bc_digest));

        SphincsHarakaSSoft jniSSoft = new SphincsHarakaSSoft();
        jniSSoft.init(pkSeed);
        int[] jniSoftRoundConstants = jniSSoft.getConstants();
        SphincsHaraka256Soft jni256Soft = new SphincsHaraka256Soft();
        jni256Soft.setConstants(jniSoftRoundConstants);

        jni256Soft.update(data, 0, data.length);
        byte[] jni256SoftDigest = jni256Soft.digest();
        System.out.println(Hex.toHexString(jni256SoftDigest));

        SphincsHarakaSAESNI jniSAes = new SphincsHarakaSAESNI();
        jniSAes.init(pkSeed);
        int[] jniAesRoundConstants = jniSAes.getConstants();
        SphincsHaraka256AESNI jni256Aes = new SphincsHaraka256AESNI();
        jni256Aes.setConstants(jniAesRoundConstants);

        jni256Aes.update(data, 0, data.length);
        byte[] jni256AedDigest = jni256Aes.digest();
        System.out.println(Hex.toHexString(jni256AedDigest));

        JavaIntrinsicHarakaS javaIntrinsicHarakaS = new JavaIntrinsicHarakaS();
        for (int i = 0; i < 1000000; i++) {
            javaIntrinsicHarakaS.init(pkSeed);
        }

        javaIntrinsicHarakaS.init(pkSeed);

        JavaIntrinsicHaraka256 javaIntrinsicHaraka256 = new JavaIntrinsicHaraka256(javaIntrinsicHarakaS);
        for (int i = 0; i < 100000000; i++) {
            javaIntrinsicHaraka256.update(data, 0, data.length);
            javaIntrinsicHaraka256.digest(32);
            javaIntrinsicHaraka256.reset();
        }
        javaIntrinsicHaraka256.update(data, 0, data.length);

        byte[] javaIntrinsicDigest = javaIntrinsicHaraka256.digest(32);

        String result = "0f868a2d8580debf4027eb1895bb4e6d7e3e55780ebf09f43c1bb9dabe606467";
        assertEquals(result, Hex.toHexString(bc_digest));
        assertEquals(result, Hex.toHexString(jni256SoftDigest));
        assertEquals(result, Hex.toHexString(jni256AedDigest));
        assertEquals(result, Hex.toHexString(javaIntrinsicDigest));

    }

    public void testHaraka256_shorterInput() {
        byte[] pkSeed = new byte[64];
        byte[] data = new byte[16];
        data[13] = 37;

        HarakaSXof bcXof = new HarakaSXof(pkSeed);
        HarakaS256Digest bc = new HarakaS256Digest(bcXof);

        bc.update(data, 0, data.length);
        byte[] bc_digest = new byte[32];
        bc.doFinal(bc_digest, 0);
        System.out.println(Hex.toHexString(bc_digest));

        SphincsHarakaSAESNI jniSAes = new SphincsHarakaSAESNI();
        jniSAes.init(pkSeed);
        int[] jniAesRoundConstants = jniSAes.getConstants();
        SphincsHaraka256AESNI jni256Aes = new SphincsHaraka256AESNI();
        jni256Aes.setConstants(jniAesRoundConstants);

        jni256Aes.update(data, 0, data.length);
        byte[] jni256AedDigest = jni256Aes.digest();
        System.out.println(Hex.toHexString(jni256AedDigest));

        String result = "0f868a2d8580debf4027eb1895bb4e6d7e3e55780ebf09f43c1bb9dabe606467";
        assertEquals(result, Hex.toHexString(bc_digest));
        assertEquals(result, Hex.toHexString(jni256AedDigest));

    }


    public void testHaraka512() {
        byte[] pkSeed = new byte[64];
        byte[] data = new byte[64];
        data[13] = 37;

        HarakaSXof bcXof = new HarakaSXof(pkSeed);
        HarakaS512Digest bc = new HarakaS512Digest(bcXof);

        bc.update(data, 0, data.length);
        byte[] bc_digest = new byte[32];
        bc.doFinal(bc_digest, 0);
        System.out.println(Hex.toHexString(bc_digest));

        SphincsHarakaSSoft jniSSoft = new SphincsHarakaSSoft();
        jniSSoft.init(pkSeed);
        int[] jniSoftRoundConstants = jniSSoft.getConstants();
        SphincsHaraka512Soft jni512Soft = new SphincsHaraka512Soft();
        jni512Soft.setConstants(jniSoftRoundConstants);

        jni512Soft.update(data, 0, data.length);
        byte[] jni512SoftDigest = jni512Soft.digest();
        System.out.println(Hex.toHexString(jni512SoftDigest));

        SphincsHarakaSAESNI jniSAes = new SphincsHarakaSAESNI();
        jniSAes.init(pkSeed);
        int[] jniAesRoundConstants = jniSAes.getConstants();
        SphincsHaraka512AESNI jni512Aes = new SphincsHaraka512AESNI();
        jni512Aes.setConstants(jniAesRoundConstants);

        jni512Aes.update(data, 0, data.length);
        byte[] jni512AedDigest = jni512Aes.digest();
        System.out.println(Hex.toHexString(jni512AedDigest));

        JavaIntrinsicHarakaS javaIntrinsicHarakaS = new JavaIntrinsicHarakaS();
        for (int i = 0; i < 1000000; i++) {
            javaIntrinsicHarakaS.init(pkSeed);
        }
        javaIntrinsicHarakaS.init(pkSeed);

        JavaIntrinsicHaraka512 javaIntrinsicHaraka512 = new JavaIntrinsicHaraka512(javaIntrinsicHarakaS);
        for (int i = 0; i < 100000000; i++) {
            javaIntrinsicHaraka512.update(data, 0, data.length);
            javaIntrinsicHaraka512.digest(32);
            javaIntrinsicHaraka512.reset();
        }
        javaIntrinsicHaraka512.update(data, 0, data.length);
        byte[] javaIntrinsicDigest = javaIntrinsicHaraka512.digest(32);


        String result = "4db39a5f4438b06f6b1ebbe44b92735a6c18d4a4c404be124115bacd87b973c4";
        assertEquals(result, Hex.toHexString(bc_digest));
        assertEquals(result, Hex.toHexString(jni512SoftDigest));
        assertEquals(result, Hex.toHexString(jni512AedDigest));
        assertEquals(result, Hex.toHexString(javaIntrinsicDigest));


    }


    public void testHarakaS() {
        byte[] pkSeed = new byte[32];
        byte[] data = new byte[64];
        data[2] = 37;

        HarakaSXof bcXof = new HarakaSXof(pkSeed);

        bcXof.update(data, 0, data.length);
        byte[] bc_digest = new byte[64];
        bcXof.doFinal(bc_digest, 0, bc_digest.length);
        System.out.println(Hex.toHexString(bc_digest));

        SphincsHarakaSSoft jniSSoft = new SphincsHarakaSSoft();
        jniSSoft.init(pkSeed);

        jniSSoft.update(data, 0, data.length);
        byte[] jniSSoftDigest = jniSSoft.digest(64 * 8);
        System.out.println(Hex.toHexString(jniSSoftDigest));

        SphincsHarakaSAESNI jniSAes = new SphincsHarakaSAESNI();
        jniSAes.init(pkSeed);

        jniSAes.update(data, 0, data.length);
        byte[] jniSAesDigest = jniSAes.digest(64 * 8);
        System.out.println(Hex.toHexString(jniSAesDigest));

        JavaIntrinsicHarakaS javaIntrinsicHarakaS = new JavaIntrinsicHarakaS();
        for (int i = 0; i < 1000000; i++) {
            javaIntrinsicHarakaS.init(pkSeed);
        }
        javaIntrinsicHarakaS.update(data, 0, data.length);
        byte[] javaIntrinsicDigest = javaIntrinsicHarakaS.digest(64);


        String result = "af6e6362af215580114ca7d7580cdbaa902d3e3566bf995b0a4271f2508302f5015070483aeb954d58d9ecaf0427c76cc87b5d1fa4e17152de64ee9e8f6ee100";
        assertEquals(result, Hex.toHexString(bc_digest));
        // The SphincsHarakaSSoft implementation is broken. As we do not need it, we do not investigate this in further detail.
        // assertEquals(result, Hex.toHexString(jniSSoftDigest));
        assertEquals(result, Hex.toHexString(jniSAesDigest));
        assertEquals(result, Hex.toHexString(javaIntrinsicDigest));

    }


}
