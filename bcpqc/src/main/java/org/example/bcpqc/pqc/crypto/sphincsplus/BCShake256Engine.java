package org.example.bcpqc.pqc.crypto.sphincsplus;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;

class BCShake256Engine
        extends AbstractDigestShake256Engine {
    private final Xof treeDigest;
    private final Xof maskDigest;

    public BCShake256Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
        super(robust, n, w, d, a, k, h);

        this.treeDigest = new SHAKEDigest(256);
        this.maskDigest = new SHAKEDigest(256);
    }

    @Override
    protected byte[] calculateTreeDigest(int N, byte[]... data) {
        for (byte[] d : data) {
            treeDigest.update(d, 0, d.length);
        }
        byte[] digest = new byte[N];
        treeDigest.doFinal(digest, 0, digest.length);
        return digest;
    }

    @Override
    protected byte[] calculateMaskDigest(int N, byte[]... data) {
        for (byte[] d : data) {
            maskDigest.update(d, 0, d.length);
        }
        byte[] digest = new byte[N];
        maskDigest.doFinal(digest, 0, digest.length);
        return digest;
    }

    @Override
    public BCShake256Engine clone() {
        return new BCShake256Engine(robust, N, WOTS_W, D, A, K, H);
    }
}
