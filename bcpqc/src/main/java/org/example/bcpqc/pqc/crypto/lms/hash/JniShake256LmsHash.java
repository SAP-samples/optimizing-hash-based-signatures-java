package org.example.bcpqc.pqc.crypto.lms.hash;

import org.example.jnihash.JniShake;

public class JniShake256LmsHash implements LMSHash {
    private final int digestSize;
    private final JniShake jniShake;

    public JniShake256LmsHash(int digestSize) {
        this.digestSize = digestSize;
        this.jniShake = new JniShake();
    }

    @Override
    public void treeLeaf(byte[] I, int r, byte[] data, byte[] out) {
        jniShake.shake256_lms_tree_leaf(I, r, data, out);
    }

    @Override
    public void treeIntermediate(byte[] I, int r, byte[] d1, byte[] d2, byte[] out) {
        jniShake.shake256_lms_tree_intermediate(I, r, d1, d2, out);
    }

    @Override
    public void otsChain(byte[] I, int q, int i, int j, byte[] data, byte[] out) {
        jniShake.shake256_lms_ots_chain(I, q, i, j, data, out);
    }
}
