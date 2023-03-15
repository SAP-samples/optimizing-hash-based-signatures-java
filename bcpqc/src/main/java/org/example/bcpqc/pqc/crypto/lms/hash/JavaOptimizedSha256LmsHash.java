package org.example.bcpqc.pqc.crypto.lms.hash;

import org.example.bcpqc.pqc.crypto.lms.LMS;
import org.example.bcpqc.pqc.crypto.xmss.khf.JavaOptimizedSHA2KHF;
import sun.security.provider.SHA2;

import static sun.security.provider.ByteArrayAccess.i2bBig;

public class JavaOptimizedSha256LmsHash implements LMSHash {
    private final SHA2.SHA256 digest;
    private final int digestSize;

    public JavaOptimizedSha256LmsHash(int digestSize) {
        this.digest = new SHA2.SHA256();
        this.digestSize = digestSize;
    }

    private void u32str_16(int n, byte[] d) {
        d[16] = (byte) (n >>> 24);
        d[17] = (byte) (n >>> 16);
        d[18] = (byte) (n >>> 8);
        d[19] = (byte) (n);
    }

    private void u16str_20(short n, byte[] d) {
        d[20] = (byte) (n >>> 8);
        d[21] = (byte) (n);
    }


    @Override
    public void treeLeaf(byte[] I, int r, byte[] data, byte[] out) {
        // I: 16, r: 4, D_LEAF: 2, data: n
        int size = 22 + digestSize;
        byte[] buffer = JavaOptimizedSHA2KHF.prepareBufferWithPadding(size);

        System.arraycopy(I, 0, buffer, 0, 16);
        u32str_16(r, buffer);
        u16str_20(LMS.D_LEAF, buffer);
        System.arraycopy(data, 0, buffer, 22, digestSize);

        digest.implCompressMultiBlock(buffer, 0, buffer.length - 1);

        int[] digestState = digest.state;
        i2bBig(digestState, 0, out, 0, digestSize);
        digest.engineReset();
    }

    @Override
    public void treeIntermediate(byte[] I, int r, byte[] d1, byte[] d2, byte[] out) {
        // I: 16, r: 4, D_LEAF: 2, data: 2 * m
        int size = 22 + 2 * digestSize;
        byte[] buffer = JavaOptimizedSHA2KHF.prepareBufferWithPadding(size);

        System.arraycopy(I, 0, buffer, 0, 16);
        u32str_16(r, buffer);
        u16str_20(LMS.D_INTR, buffer);
        System.arraycopy(d1, 0, buffer, 22, digestSize);
        System.arraycopy(d2, 0, buffer, 22 + digestSize, digestSize);

        digest.implCompressMultiBlock(buffer, 0, buffer.length - 1);

        int[] digestState = digest.state;
        i2bBig(digestState, 0, out, 0, digestSize);
        digest.engineReset();
    }

    @Override
    public void otsChain(byte[] I, int q, int i, int j, byte[] data, byte[] out) {
        // I: 16, q: 4, i: 2, j: 1, data: n
        int size = 23 + digestSize;
        byte[] buffer = JavaOptimizedSHA2KHF.prepareBufferWithPadding(size);

        System.arraycopy(I, 0, buffer, 0, 16);
        u32str_16(q, buffer);
        u16str_20((short) i, buffer);
        buffer[22] = (byte) j;
        System.arraycopy(data, 0, buffer, 23, digestSize);

        digest.implCompressMultiBlock(buffer, 0, buffer.length - 1);

        int[] digestState = digest.state;
        i2bBig(digestState, 0, out, 0, digestSize);
        digest.engineReset();
    }
}
