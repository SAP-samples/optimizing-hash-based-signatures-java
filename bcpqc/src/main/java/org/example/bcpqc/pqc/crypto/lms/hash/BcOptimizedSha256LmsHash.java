package org.example.bcpqc.pqc.crypto.lms.hash;

import org.example.bcpqc.crypto.digests.SHA256Digest;
import org.example.bcpqc.pqc.crypto.lms.LMS;
import org.example.bcpqc.pqc.crypto.lms.LmsUtils;

public class BcOptimizedSha256LmsHash implements LMSHash {
    private final SHA256Digest digest;
    private final int digestSize;

    private final byte[] rqBuf = new byte[4];

    public BcOptimizedSha256LmsHash(int digestSize) {
        this.digest = new SHA256Digest();
        this.digestSize = digestSize;
    }

    private void u32str(int n) {
        rqBuf[0] = (byte) (n >>> 24);
        rqBuf[1] = (byte) (n >>> 16);
        rqBuf[2] = (byte) (n >>> 8);
        rqBuf[3] = (byte) (n);
        digest.processMultipleWords(rqBuf);
    }

    private void consumeIRqDi(byte[] I, int rq, int di) {
        digest.processMultipleWords(I);

        u32str(rq);
        LmsUtils.u16str((short) di, digest);
    }

    private void doFinal(byte[] out) {
        if (digestSize < digest.getDigestSize()) {
            byte[] buffer = new byte[digest.getDigestSize()];
            digest.doFinal(buffer, 0);
            System.arraycopy(buffer, 0, out, 0, digestSize);
        } else {
            digest.doFinal(out, 0);
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
        digest.update(d1, 0, d1.length);
        digest.update(d2, 0, d2.length);
        this.doFinal(out);
    }

    @Override
    public void otsChain(byte[] I, int q, int i, int j, byte[] data, byte[] out) {
        consumeIRqDi(I, q, i);
        digest.update((byte) j);
        digest.update(data, 0, data.length);
        this.doFinal(out);
    }
}
