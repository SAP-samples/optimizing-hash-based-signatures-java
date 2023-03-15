package org.example.bcpqc.pqc.crypto.lms.hash;

import org.example.jnihash.JniHash;


public class JniSha2LmsHash implements LMSHash {
    private final JniHash jniHash = new JniHash();
    private final int digestSize;


    public JniSha2LmsHash(int digestSize) {
        this.digestSize = digestSize;
    }

    @Override
    public void treeLeaf(byte[] I, int r, byte[] data, byte[] out) {
        jniHash.sha2_lms_tree_leaf(I, r, data, out);
    }

    @Override
    public void treeIntermediate(byte[] I, int r, byte[] d1, byte[] d2, byte[] out) {
        jniHash.sha2_lms_tree_intermediate(I, r, d1, d2, out);
    }

    @Override
    public void otsChain(byte[] I, int q, int i, int j, byte[] data, byte[] out) {
        jniHash.sha2_lms_ots_chain(I, q, i, j, data, out);
    }
}
