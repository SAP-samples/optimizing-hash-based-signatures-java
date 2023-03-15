package org.example.bcpqc.pqc.crypto.sphincsplus;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.MGF1BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.MGFParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.example.bcpqc.crypto.digests.SHA256Digest;

public class BCSha2Engine extends AbstractDigestSha2Engine {

    private final MGF1BytesGenerator mgf1;
    private final HMac treeHMac;
    private final byte[] hmacBuf;
    private final Digest msgDigest;
    private final byte[] msgDigestBuf;
    private Memoable msgMemo;
    private Memoable sha256Memo;
    private final Digest sha256 = new SHA256Digest();
    private final byte[] sha256Buf = new byte[sha256.getDigestSize()];


    public BCSha2Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
        super(robust, n, w, d, a, k, h);
        if (n == 16) {
            this.msgDigest = new SHA256Digest();
            this.treeHMac = new HMac(new SHA256Digest());
            this.mgf1 = new MGF1BytesGenerator(new SHA256Digest());
        } else {
            this.msgDigest = new SHA512Digest();
            this.treeHMac = new HMac(new SHA512Digest());
            this.mgf1 = new MGF1BytesGenerator(new SHA512Digest());
        }

        this.hmacBuf = new byte[treeHMac.getMacSize()];
        this.msgDigestBuf = new byte[msgDigest.getDigestSize()];
    }

    public BCSha2Engine clone() {
        BCSha2Engine clone = new BCSha2Engine(robust, N, WOTS_W, D, A, K, H);
        clone.sha256Memo = this.sha256Memo;
        clone.msgMemo = this.msgMemo;
        return clone;
    }

    @Override
    public byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message) {
        treeHMac.init(new KeyParameter(prf));
        treeHMac.update(randomiser, 0, randomiser.length);
        treeHMac.update(message, 0, message.length);
        treeHMac.doFinal(hmacBuf, 0);

        return Arrays.copyOfRange(hmacBuf, 0, N);

    }

    protected void mgf1GenerateMask256(byte[] buf, byte[] key) {
        MGF1BytesGenerator mgf1 = new MGF1BytesGenerator(new SHA256Digest());

        mgf1.init(new MGFParameters(key));

        mgf1.generateBytes(buf, 0, buf.length);
    }

    @Override
    protected void mgf1GenerateMask(byte[] buf, byte[] key) {
        mgf1.init(new MGFParameters(key));

        mgf1.generateBytes(buf, 0, buf.length);

    }

    protected byte[] calculateMsgDigest(byte[]... data) {
        return this.calculateMsgDigest(this.msgDigest.getDigestSize(), data);
    }


    @Override
    protected byte[] calculateMsgDigest(int N, byte[]... data) {
        for (byte[] d : data) {
            msgDigest.update(d, 0, d.length);

        }
        if (N < msgDigest.getDigestSize()) {
            msgDigest.doFinal(msgDigestBuf, 0);
            return Arrays.copyOfRange(msgDigestBuf, 0, N);
        } else {
            byte[] dig = new byte[msgDigest.getDigestSize()];
            msgDigest.doFinal(dig, 0);
            return dig;
        }
    }

    @Override
    protected byte[] calculateSha256Digest(int N, byte[]... data) {
        for (byte[] d : data) {
            sha256.update(d, 0, d.length);

        }
        if (N < sha256.getDigestSize()) {
            sha256.doFinal(sha256Buf, 0);
            return Arrays.copyOfRange(sha256Buf, 0, N);
        } else {
            byte[] dig = new byte[sha256.getDigestSize()];
            sha256.doFinal(dig, 0);
            return dig;
        }
    }

    @Override
    protected byte[] calculateSha256DigestFromMemo(int N, byte[]... data) {
        ((Memoable) sha256).reset(sha256Memo);
        return calculateSha256Digest(N, data);
    }

    @Override
    protected byte[] calculateMsgDigestFromMemo(int N, byte[]... data) {
        ((Memoable) msgDigest).reset(msgMemo);
        return calculateMsgDigest(N, data);
    }


    @Override
    public void init(byte[] pkSeed) {
        final byte[] padding = new byte[bl];

        msgDigest.update(pkSeed, 0, pkSeed.length);
        msgDigest.update(padding, 0, bl - N); // toByte(0, 64 - n)
        msgMemo = ((Memoable) msgDigest).copy();

        msgDigest.reset();

        sha256.update(pkSeed, 0, pkSeed.length);
        sha256.update(padding, 0, 64 - pkSeed.length); // toByte(0, 64 - n)
        sha256Memo = ((Memoable) sha256).copy();

        sha256.reset();
    }
}
