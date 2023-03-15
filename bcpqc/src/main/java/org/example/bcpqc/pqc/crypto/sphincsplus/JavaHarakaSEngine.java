package org.example.bcpqc.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.example.bcpqc.crypto.digests.haraka.JavaIntrinsicHaraka256;
import org.example.bcpqc.crypto.digests.haraka.JavaIntrinsicHaraka512;
import org.example.bcpqc.crypto.digests.haraka.JavaIntrinsicHarakaS;

public class JavaHarakaSEngine
        extends SPHINCSPlusEngine {
    private JavaIntrinsicHarakaS harakaS;
    private JavaIntrinsicHaraka256 haraka256;
    private JavaIntrinsicHaraka512 haraka512;

    public JavaHarakaSEngine(boolean robust, int n, int w, int d, int a, int k, int h) {
        super(robust, n, w, d, a, k, h);
    }

    public void init(byte[] pkSeed) {
        harakaS = new JavaIntrinsicHarakaS();
        harakaS.init(pkSeed);
        haraka256 = new JavaIntrinsicHaraka256(harakaS);
        haraka512 = new JavaIntrinsicHaraka512(harakaS);
    }

    public JavaHarakaSEngine clone() {
        JavaHarakaSEngine clone = new JavaHarakaSEngine(robust, N, WOTS_W, D, A, K, H);
        clone.harakaS = this.harakaS.clone();
        clone.haraka256 = new JavaIntrinsicHaraka256(clone.harakaS);
        clone.haraka512 = new JavaIntrinsicHaraka512(clone.harakaS);
        return clone;
    }

    public byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1) {
        byte[] hash;
        haraka512.update(adrs.value, 0, adrs.value.length);
        if (robust) {
            haraka256.update(adrs.value, 0, adrs.value.length);
            hash = haraka256.digest(32);
            haraka256.reset();
            for (int i = 0; i < m1.length; ++i) {
                hash[i] ^= m1[i];
            }
            haraka512.update(hash, 0, m1.length);
        } else {
            haraka512.update(m1, 0, m1.length);
        }
        // NOTE The digest implementation implicitly pads the input with zeros up to 64 length
        hash = haraka512.digest(N);
        haraka512.reset();
        return hash;
    }

    public byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2) {
        byte[] m = new byte[m1.length + m2.length];
        System.arraycopy(m1, 0, m, 0, m1.length);
        System.arraycopy(m2, 0, m, m1.length, m2.length);
        m = bitmask(adrs, m);
        harakaS.update(adrs.value, 0, adrs.value.length);
        harakaS.update(m, 0, m.length);
        byte[] r = harakaS.digest(N);
        harakaS.reset();
        return r;
    }

    public IndexedDigest H_msg(byte[] prf, byte[] pkSeed, byte[] pkRoot, byte[] message) {
        int forsMsgBytes = ((A * K) + 7) >> 3;
        int leafBits = H / D;
        int treeBits = H - leafBits;
        int leafBytes = (leafBits + 7) >> 3;
        int treeBytes = (treeBits + 7) >> 3;

        harakaS.update(prf, 0, prf.length);
        harakaS.update(pkRoot, 0, pkRoot.length);
        harakaS.update(message, 0, message.length);
        byte[] out = harakaS.digest(forsMsgBytes + leafBytes + treeBytes);
        harakaS.reset();

        byte[] treeIndexBuf = new byte[8];
        System.arraycopy(out, forsMsgBytes, treeIndexBuf, 8 - treeBytes, treeBytes);
        long treeIndex = Pack.bigEndianToLong(treeIndexBuf, 0);
        treeIndex &= (~0L) >>> (64 - treeBits);

        byte[] leafIndexBuf = new byte[4];
        System.arraycopy(out, forsMsgBytes + treeBytes, leafIndexBuf, 4 - leafBytes, leafBytes);

        int leafIndex = Pack.bigEndianToInt(leafIndexBuf, 0);
        leafIndex &= (~0) >>> (32 - leafBits);
        return new IndexedDigest(treeIndex, leafIndex, Arrays.copyOfRange(out, 0, forsMsgBytes));
    }

    public byte[] T_l(byte[] pkSeed, ADRS adrs, byte[] m) {
        m = bitmask(adrs, m);

        harakaS.update(adrs.value, 0, adrs.value.length);
        harakaS.update(m, 0, m.length);

        byte[] rv = harakaS.digest(N);
        harakaS.reset();
        return rv;
    }

    public byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs) {
        haraka512.update(adrs.value, 0, adrs.value.length);
        haraka512.update(skSeed, 0, skSeed.length);
        byte[] rv = haraka512.digest(N);
        haraka512.reset();
        return rv;
    }

    public byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message) {
        harakaS.update(prf, 0, prf.length);
        harakaS.update(randomiser, 0, randomiser.length);
        harakaS.update(message, 0, message.length);
        byte[] rv = harakaS.digest(N);
        harakaS.reset();
        return rv;
    }

    protected byte[] bitmask(ADRS adrs, byte[] m) {
        if (robust) {
            harakaS.update(adrs.value, 0, adrs.value.length);
            byte[] mask = harakaS.digest(m.length);
            harakaS.reset();


            for (int i = 0; i < m.length; ++i) {
                m[i] ^= mask[i];
            }
            return m;
        }
        return m;
    }

}
