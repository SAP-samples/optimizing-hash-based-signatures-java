package org.example.bcpqc.pqc.crypto.lms.hash;

import org.example.jnihash.JniHash;

public class JniFixedPaddingSha2LmsHash implements LMSHash {
    private final JniHash jniHash = new JniHash();
    private final int digestSize;

    private static final int _440 = 5;
    private static final int _432 = 6;
    private static final int _688 = 7;
    private static final int _376 = 8;
    private static final int _368 = 9;
    private static final int _560 = 10;

    public JniFixedPaddingSha2LmsHash(int digestSize) {
        this.digestSize = digestSize;
    }

    @Override
    public void treeLeaf(byte[] I, int r, byte[] data, byte[] out) {
        if (digestSize == 32) {
            jniHash.sha2_lms_tree_leaf_fixed_padding(I, r, data, _432, out);
        } else {
            jniHash.sha2_lms_tree_leaf_fixed_padding(I, r, data, _368, out);
        }
    }

    @Override
    public void treeIntermediate(byte[] I, int r, byte[] d1, byte[] d2, byte[] out) {
        if (digestSize == 32) {
            jniHash.sha2_lms_tree_intermediate_fixed_padding(I, r, d1, d2, _688, out);
        } else {
            jniHash.sha2_lms_tree_intermediate_fixed_padding(I, r, d1, d2, _560, out);
        }
    }

    @Override
    public void otsChain(byte[] I, int q, int i, int j, byte[] data, byte[] out) {
        if (digestSize == 32) {
            jniHash.sha2_lms_ots_chain_fixed_padding(I, q, i, j, data, _440, out);
        } else {
            jniHash.sha2_lms_ots_chain_fixed_padding(I, q, i, j, data, _376, out);
        }
    }
}
