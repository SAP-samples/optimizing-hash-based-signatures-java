package org.example.bcpqc.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.example.jnihash.JniShake;

public class JNIShake256Engine extends SPHINCSPlusEngine {
    private final JniShake shake;
    private byte[] pkSeed;

    public JNIShake256Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
        super(robust, n, w, d, a, k, h);
        this.shake = new JniShake();
        this.shake.shake256_sphincs_init(new byte[0], n, robust);
    }

    @Override
    public void init(byte[] pkSeed) {
        this.shake.shake256_sphincs_init(pkSeed, N, robust);
        this.pkSeed = pkSeed;
    }

    public JNIShake256Engine clone() {
        JNIShake256Engine clone = new JNIShake256Engine(robust, N, WOTS_W, D, A, K, H);
        clone.shake.shake256_sphincs_init(pkSeed, N, robust);

        return clone;
    }

    @Override
    public byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1) {
        byte[] out = new byte[N];
        this.shake.shake256_sphincs_th(adrs.value, m1, out);
        return out;
    }

    @Override
    public byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2) {
        byte[] m1m2 = new byte[2 * N];
        byte[] out = new byte[N];
        System.arraycopy(m1, 0, m1m2, 0, N);
        System.arraycopy(m2, 0, m1m2, N, N);
        this.shake.shake256_sphincs_th(adrs.value, m1m2, out);
        return out;
    }

    @Override
    public IndexedDigest H_msg(byte[] R, byte[] pkSeed, byte[] pkRoot, byte[] message) {
        int forsMsgBytes = ((A * K) + 7) / 8;
        int leafBits = H / D;
        int treeBits = H - leafBits;
        int leafBytes = (leafBits + 7) / 8;
        int treeBytes = (treeBits + 7) / 8;
        int m = forsMsgBytes + leafBytes + treeBytes;

        byte[] out = new byte[m];
        this.shake.shake256_h_msh(R, pkRoot, message, out);

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

    @Override
    public byte[] T_l(byte[] pkSeed, ADRS adrs, byte[] m) {
        byte[] out = new byte[N];
        this.shake.shake256_sphincs_th(adrs.value, m, out);
        return out;
    }

    @Override
    public byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs) {
        byte[] out = new byte[N];
        this.shake.shake256_sphincs_prf(skSeed, adrs.value, out);
        return out;
    }

    @Override
    public byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message) {
        byte[] out = new byte[N];
        this.shake.shake256_sphincs_prf_msg(prf, randomiser, message, out);
        return out;
    }
}
