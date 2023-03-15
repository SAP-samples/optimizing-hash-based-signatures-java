package org.example.bcpqc.pqc.crypto.sphincsplus;

import sun.security.provider.SHAKE256;

public class JavaShake256Engine extends AbstractDigestShake256Engine {

    private SHAKE256 treeDigest;
    private SHAKE256 maskDigest;

    public JavaShake256Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
        super(robust, n, w, d, a, k, h);

        treeDigest = new SHAKE256(N);
        // DigestLength param will be ignored
        maskDigest = new SHAKE256(N);
    }

    public JavaShake256Engine clone() {
        return new JavaShake256Engine(robust, N, WOTS_W, D, A, K, H);
    }

    @Override
    protected byte[] calculateTreeDigest(int N, byte[]... data) {
        for (byte[] d : data) {
            treeDigest.engineUpdate(d, 0, d.length);
        }
        byte[] out = new byte[N];
        treeDigest.digest(out, 0, out.length);
        return out;
    }

    @Override
    protected byte[] calculateMaskDigest(int N, byte[]... data) {
        for (byte[] d : data) {
            maskDigest.engineUpdate(d, 0, d.length);
        }
        byte[] mask = new byte[N];
        maskDigest.digest(mask, 0, mask.length);
        return mask;
    }
}
