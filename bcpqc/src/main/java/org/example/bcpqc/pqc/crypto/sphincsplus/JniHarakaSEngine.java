package org.example.bcpqc.pqc.crypto.sphincsplus;


import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.example.jnihash.haraka.SphincsHaraka256AESNI;
import org.example.jnihash.haraka.SphincsHaraka512AESNI;
import org.example.jnihash.haraka.SphincsHarakaSAESNI;

class JniHarakaSEngine
        extends SPHINCSPlusEngine {
    private SphincsHarakaSAESNI harakaS;
    private SphincsHaraka256AESNI haraka256;
    private SphincsHaraka512AESNI haraka512;

    public JniHarakaSEngine(boolean robust, int n, int w, int d, int a, int k, int h) {
        super(robust, n, w, d, a, k, h);
    }

    public void init(byte[] pkSeed) {
        harakaS = new SphincsHarakaSAESNI();
        harakaS.init(pkSeed);

        haraka256 = new SphincsHaraka256AESNI();
        haraka256.setConstants(harakaS.getConstants());

        haraka512 = new SphincsHaraka512AESNI();
        haraka512.setConstants(harakaS.getConstants());
    }

    public JniHarakaSEngine clone() {
        JniHarakaSEngine clone = new JniHarakaSEngine(robust, N, WOTS_W, D, A, K, H);
        clone.harakaS = new SphincsHarakaSAESNI();
        clone.harakaS.setConstants(this.harakaS.getConstants());

        clone.haraka256 = new SphincsHaraka256AESNI();
        clone.haraka256.setConstants(this.harakaS.getConstants());

        clone.haraka512 = new SphincsHaraka512AESNI();
        clone.haraka512.setConstants(this.harakaS.getConstants());

        return clone;
    }

    public byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1) {
        haraka512.update(adrs.value, 0, adrs.value.length);
        if (robust) {
            haraka256.reset();
            haraka256.update(adrs.value, 0, adrs.value.length);
            byte[] hash = haraka256.digest();
            haraka256.reset();

            for (int i = 0; i < m1.length; ++i) {
                hash[i] ^= m1[i];
            }
            haraka512.update(hash, 0, m1.length);
        } else {
            haraka512.update(m1, 0, m1.length);
        }

        byte[] r = haraka512.digest(N);
        haraka512.reset();
        return r;
    }

    public byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2) {
        byte[] m = new byte[m1.length + m2.length];
        System.arraycopy(m1, 0, m, 0, m1.length);
        System.arraycopy(m2, 0, m, m1.length, m2.length);
        m = bitmask(adrs, m);
        harakaS.update(adrs.value, 0, adrs.value.length);
        harakaS.update(m, 0, m.length);
        byte[] r = harakaS.digest(N * 8);
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
        byte[] out = harakaS.digest((forsMsgBytes + leafBytes + treeBytes) * 8);
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
        byte[] r = harakaS.digest(N * 8);
        harakaS.reset();
        return r;
    }

    public byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs) {
        haraka512.update(adrs.value, 0, adrs.value.length);
        haraka512.update(skSeed, 0, skSeed.length);
        byte[] r = haraka512.digest(N);
        haraka512.reset();
        return r;
    }

    public byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message) {
        harakaS.update(prf, 0, prf.length);
        harakaS.update(randomiser, 0, randomiser.length);
        harakaS.update(message, 0, message.length);
        byte[] r = harakaS.digest(N * 8);
        harakaS.reset();
        return r;
    }

    protected byte[] bitmask(ADRS adrs, byte[] m) {
        if (robust) {
            harakaS.update(adrs.value, 0, adrs.value.length);
            byte[] mask = harakaS.digest(m.length * 8);
            harakaS.reset();

            for (int i = 0; i < m.length; ++i) {
                m[i] ^= mask[i];
            }
            return m;
        }
        return m;
    }
}
