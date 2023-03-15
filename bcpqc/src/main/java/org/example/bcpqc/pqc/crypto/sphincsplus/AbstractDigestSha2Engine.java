package org.example.bcpqc.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

abstract class AbstractDigestSha2Engine
        extends SPHINCSPlusEngine {
    protected final int bl;

    public AbstractDigestSha2Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
        super(robust, n, w, d, a, k, h);
        if (n == 16) {
            this.bl = 64;
        } else {
            this.bl = 128;
        }
    }

    protected abstract byte[] calculateSha256Digest(int N, byte[]... data);

    protected abstract byte[] calculateSha256DigestFromMemo(int N, byte[]... data);

    public abstract void init(byte[] pkSeed);

    public byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1) {
        byte[] compressedADRS = compressedADRS(adrs);

        if (robust) {
            m1 = bitmask256(Arrays.concatenate(pkSeed, compressedADRS), m1);
        }

        return this.calculateSha256DigestFromMemo(N, compressedADRS, m1);
    }

    public byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2) {
        byte[] compressedADRS = compressedADRS(adrs);

        if (robust) {
            byte[] m1m2 = bitmask(Arrays.concatenate(pkSeed, compressedADRS), m1, m2);
            return this.calculateMsgDigestFromMemo(N, compressedADRS, m1m2);
        } else {
            return this.calculateMsgDigestFromMemo(N, compressedADRS, m1, m2);
        }
    }

    protected abstract byte[] calculateMsgDigest(int N, byte[]... data);

    protected abstract byte[] calculateMsgDigest(byte[]... data);

    protected abstract byte[] calculateMsgDigestFromMemo(int N, byte[]... data);

    public IndexedDigest H_msg(byte[] prf, byte[] pkSeed, byte[] pkRoot, byte[] message) {
        int forsMsgBytes = ((A * K) + 7) / 8;
        int leafBits = H / D;
        int treeBits = H - leafBits;
        int leafBytes = (leafBits + 7) / 8;
        int treeBytes = (treeBits + 7) / 8;
        int m = forsMsgBytes + leafBytes + treeBytes;
        byte[] out = new byte[m];

        // N=64 to avoid truncating hash
        byte[] dig = this.calculateMsgDigest(prf, pkSeed, pkRoot, message);

        out = bitmask(Arrays.concatenate(prf, pkSeed, dig), out);

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
        byte[] compressedADRS = compressedADRS(adrs);
        if (robust) {
            m = bitmask(Arrays.concatenate(pkSeed, compressedADRS), m);
        }

        return this.calculateMsgDigestFromMemo(N, compressedADRS, m);
    }

    public byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs) {
        int n = skSeed.length;
        byte[] compressedADRS = compressedADRS(adrs);

        return this.calculateSha256DigestFromMemo(n, compressedADRS, skSeed);
    }

    public abstract byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message);

    private byte[] compressedADRS(ADRS adrs) {
        byte[] rv = new byte[22];
        System.arraycopy(adrs.value, ADRS.OFFSET_LAYER + 3, rv, 0, 1); // LSB layer address
        System.arraycopy(adrs.value, ADRS.OFFSET_TREE + 4, rv, 1, 8); // LS 8 bytes Tree address
        System.arraycopy(adrs.value, ADRS.OFFSET_TYPE + 3, rv, 9, 1); // LSB type
        System.arraycopy(adrs.value, 20, rv, 10, 12);

        return rv;
    }

    protected byte[] bitmask(byte[] key, byte[] m) {
        byte[] mask = new byte[m.length];

        this.mgf1GenerateMask(mask, key);

        for (int i = 0; i < m.length; ++i) {
            mask[i] ^= m[i];
        }

        return mask;
    }

    protected byte[] bitmask(byte[] key, byte[] m1, byte[] m2) {
        byte[] mask = new byte[m1.length + m2.length];

        this.mgf1GenerateMask(mask, key);

        for (int i = 0; i < m1.length; ++i) {
            mask[i] ^= m1[i];
        }
        for (int i = 0; i < m2.length; ++i) {
            mask[i + m1.length] ^= m2[i];
        }
        return mask;
    }

    protected byte[] bitmask256(byte[] key, byte[] m) {
        byte[] mask = new byte[m.length];

        mgf1GenerateMask256(mask, key);

        for (int i = 0; i < m.length; ++i) {
            mask[i] ^= m[i];
        }

        return mask;
    }


    protected abstract void mgf1GenerateMask(byte[] buf, byte[] key);

    protected abstract void mgf1GenerateMask256(byte[] buf, byte[] key);

}
