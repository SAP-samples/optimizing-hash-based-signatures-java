package org.example.bcpqc.pqc.crypto.lms.hash;

import org.bouncycastle.crypto.Digest;
import org.example.bcpqc.pqc.crypto.lms.LMS;
import org.example.bcpqc.pqc.crypto.lms.LmsUtils;

public class BcDigestLmsHash implements LMSHash {
    private final Digest digest;
    private final int digestSize;

    public BcDigestLmsHash(Digest digest, int digestSize) {
        this.digest = digest;
        this.digestSize = digestSize;
    }

    private void consumeIRqDi(byte[] I, int rq, int di) {
        digest.update(I, 0, I.length);

        LmsUtils.u32str(rq, digest);
        LmsUtils.u16str((short) di, digest);
    }

    private void doFinal(byte[] out) {
        if(digestSize < digest.getDigestSize()){
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
