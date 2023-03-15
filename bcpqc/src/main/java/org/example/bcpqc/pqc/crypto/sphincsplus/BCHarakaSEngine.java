package org.example.bcpqc.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class BCHarakaSEngine
        extends SPHINCSPlusEngine {
    private HarakaSXof harakaSXof;
    private HarakaS256Digest harakaS256Digest;
    private HarakaS512Digest harakaS512Digest;

    public BCHarakaSEngine(boolean robust, int n, int w, int d, int a, int k, int h) {
        super(robust, n, w, d, a, k, h);
    }

    @Override
    public BCHarakaSEngine clone() {
        BCHarakaSEngine clone = new BCHarakaSEngine(robust, N, WOTS_W, D, A, K, H);
        clone.harakaSXof = this.harakaSXof.clone();
        clone.harakaS256Digest = new HarakaS256Digest(harakaSXof);
        clone.harakaS512Digest = new HarakaS512Digest(harakaSXof);
        return clone;
    }

    public void init(byte[] pkSeed) {
        harakaSXof = new HarakaSXof(pkSeed);
        harakaS256Digest = new HarakaS256Digest(harakaSXof);
        harakaS512Digest = new HarakaS512Digest(harakaSXof);
    }

    public byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1) {
        byte[] hash = new byte[32];
        harakaS512Digest.update(adrs.value, 0, adrs.value.length);
        if (robust) {
            harakaS256Digest.update(adrs.value, 0, adrs.value.length);
            harakaS256Digest.doFinal(hash, 0);
            for (int i = 0; i < m1.length; ++i) {
                hash[i] ^= m1[i];
            }
            harakaS512Digest.update(hash, 0, m1.length);
        } else {
            harakaS512Digest.update(m1, 0, m1.length);
        }
        // NOTE The digest implementation implicitly pads the input with zeros up to 64 length
        harakaS512Digest.doFinal(hash, 0);
        return Arrays.copyOf(hash, N);
    }

    public byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2) {
        byte[] rv = new byte[N];
        byte[] m = new byte[m1.length + m2.length];
        System.arraycopy(m1, 0, m, 0, m1.length);
        System.arraycopy(m2, 0, m, m1.length, m2.length);
        m = bitmask(adrs, m);
        harakaSXof.update(adrs.value, 0, adrs.value.length);
        harakaSXof.update(m, 0, m.length);
        harakaSXof.doFinal(rv, 0, rv.length);
        return rv;
    }

    public IndexedDigest H_msg(byte[] prf, byte[] pkSeed, byte[] pkRoot, byte[] message) {
        int forsMsgBytes = ((A * K) + 7) >> 3;
        int leafBits = H / D;
        int treeBits = H - leafBits;
        int leafBytes = (leafBits + 7) >> 3;
        int treeBytes = (treeBits + 7) >> 3;
        byte[] out = new byte[forsMsgBytes + leafBytes + treeBytes];
        harakaSXof.update(prf, 0, prf.length);
        harakaSXof.update(pkRoot, 0, pkRoot.length);
        harakaSXof.update(message, 0, message.length);
        harakaSXof.doFinal(out, 0, out.length);
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
        byte[] rv = new byte[N];
        m = bitmask(adrs, m);
        harakaSXof.update(adrs.value, 0, adrs.value.length);
        harakaSXof.update(m, 0, m.length);
        harakaSXof.doFinal(rv, 0, rv.length);
        return rv;
    }

    public byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs) {
        byte[] rv = new byte[32];
        harakaS512Digest.update(adrs.value, 0, adrs.value.length);
        harakaS512Digest.update(skSeed, 0, skSeed.length);
        harakaS512Digest.doFinal(rv, 0);
        return Arrays.copyOf(rv, N);
    }

    public byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message) {
        byte[] rv = new byte[N];
        harakaSXof.update(prf, 0, prf.length);
        harakaSXof.update(randomiser, 0, randomiser.length);
        harakaSXof.update(message, 0, message.length);
        harakaSXof.doFinal(rv, 0, rv.length);
        return rv;
    }

    protected byte[] bitmask(ADRS adrs, byte[] m) {
        if (robust) {
            byte[] mask = new byte[m.length];
            harakaSXof.update(adrs.value, 0, adrs.value.length);
            harakaSXof.doFinal(mask, 0, mask.length);
            for (int i = 0; i < m.length; ++i) {
                m[i] ^= mask[i];
            }
            return m;
        }
        return m;
    }
}
