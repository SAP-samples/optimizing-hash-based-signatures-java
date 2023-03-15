package org.example.bcpqc.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public abstract class AbstractDigestShake256Engine extends SPHINCSPlusEngine {
    public AbstractDigestShake256Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
        super(robust, n, w, d, a, k, h);
    }

    public void init(byte[] pkSeed) {

    }

    protected abstract byte[] calculateTreeDigest(int N, byte[]... data);

    protected abstract byte[] calculateMaskDigest(int N, byte[]... data);

    public byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1) {
        byte[] mTheta = m1;
        if (robust) {
            mTheta = bitmask(pkSeed, adrs, m1);
        }

        return this.calculateTreeDigest(N, pkSeed, adrs.value, mTheta);
    }

    public byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2) {
        if (robust) {
            byte[] m1m2 = bitmask(pkSeed, adrs, m1, m2);
            return this.calculateTreeDigest(N, pkSeed, adrs.value, m1m2);

        } else {
            return this.calculateTreeDigest(N, pkSeed, adrs.value, m1, m2);
        }
    }

    public IndexedDigest H_msg(byte[] R, byte[] pkSeed, byte[] pkRoot, byte[] message) {
        int forsMsgBytes = ((A * K) + 7) / 8;
        int leafBits = H / D;
        int treeBits = H - leafBits;
        int leafBytes = (leafBits + 7) / 8;
        int treeBytes = (treeBits + 7) / 8;
        int m = forsMsgBytes + leafBytes + treeBytes;

        byte[] out = this.calculateTreeDigest(m, R, pkSeed, pkRoot, message);

        // tree index
        // currently, only indexes up to 64 bits are supported
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
        byte[] mTheta = m;
        if (robust) {
            mTheta = bitmask(pkSeed, adrs, m);
        }

        return this.calculateTreeDigest(N, pkSeed, adrs.value, mTheta);
    }

    public byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs) {
        return this.calculateTreeDigest(N, pkSeed, adrs.value, skSeed);
    }

    public byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message) {
        return this.calculateTreeDigest(N, prf, randomiser, message);
    }

    protected byte[] bitmask(byte[] pkSeed, ADRS adrs, byte[] m) {
        byte[] mask = this.calculateMaskDigest(m.length, pkSeed, adrs.value);

        for (int i = 0; i < m.length; ++i) {
            mask[i] ^= m[i];
        }

        return mask;
    }

    protected byte[] bitmask(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2) {
        byte[] mask = calculateMaskDigest(m1.length + m2.length, pkSeed, adrs.value);

        for (int i = 0; i < m1.length; ++i) {
            mask[i] ^= m1[i];
        }
        for (int i = 0; i < m2.length; ++i) {
            mask[i + m1.length] ^= m2[i];
        }

        return mask;
    }

}
