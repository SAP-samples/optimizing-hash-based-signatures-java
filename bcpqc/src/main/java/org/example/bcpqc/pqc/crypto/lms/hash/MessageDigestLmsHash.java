package org.example.bcpqc.pqc.crypto.lms.hash;

import org.example.bcpqc.pqc.crypto.lms.LMS;

import java.security.DigestException;
import java.security.MessageDigest;

public class MessageDigestLmsHash implements LMSHash {
    private final MessageDigest digest;
    private final int digestSize;

    public MessageDigestLmsHash(MessageDigest digest, int digestSize) {
        this.digest = digest;
        this.digestSize = digestSize;
    }

    private void consumeU32str(int n) {
        digest.update((byte) (n >>> 24));
        digest.update((byte) (n >>> 16));
        digest.update((byte) (n >>> 8));
        digest.update((byte) (n));
    }

    private void consumeU16str(short n) {
        digest.update((byte) (n >>> 8));
        digest.update((byte) (n));
    }
    private void consumeIRqDi(byte[] I, int rq, int di) {
        digest.update(I);

        consumeU32str(rq);
        consumeU16str((short) di);
    }

    private void doFinal(byte[] out) {
        try {
            if(digestSize < digest.getDigestLength()){
                System.arraycopy(digest.digest(), 0, out, 0, digestSize);
            } else {
                digest.digest(out, 0, digestSize);
            }
        } catch (DigestException e) {
            throw new RuntimeException(e);
        }
    }
    @Override
    public void treeLeaf(byte[] I, int r, byte[] data, byte[] out) {
        consumeIRqDi(I, r, LMS.D_LEAF);
        digest.update(data, 0, data.length);
        this.doFinal(out);
    }

    @Override
    public void treeIntermediate(byte[] I, int r, byte[] d1, byte[] d2, byte[] out) {
        consumeIRqDi(I, r, LMS.D_INTR);
        digest.update(d1);
        digest.update(d2 );
        this.doFinal(out);
    }

    @Override
    public void otsChain(byte[] I, int q, int i, int j, byte[] data, byte[] out) {
        consumeIRqDi(I, q, i);
        digest.update((byte) j);
        digest.update(data);
        this.doFinal(out);
    }
}
