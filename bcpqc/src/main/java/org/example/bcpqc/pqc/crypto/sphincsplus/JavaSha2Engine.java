package org.example.bcpqc.pqc.crypto.sphincsplus;

import sun.security.provider.DigestBase;
import sun.security.provider.SHA2;
import sun.security.provider.SHA5;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

public class JavaSha2Engine extends AbstractDigestSha2Engine {
    private final Mac treeHMac;
    private final byte[] hmacBuf;
    private final String hmacAlgo;
    private final DigestBase msgDigest;
    private final SHA2.SHA256 sha256;
    private final int msgDigestSize;
    private DigestBase msgMemo;
    private SHA2.SHA256 sha256Memo;

    public JavaSha2Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
        super(robust, n, w, d, a, k, h);
        if (n == 16) {
            this.msgDigest = new SHA2.SHA256();
            msgDigestSize = 32;
            this.hmacAlgo = "HmacSHA256";
        } else {
            this.msgDigest = new SHA5.SHA512();
            msgDigestSize = 64;
            this.hmacAlgo = "HmacSHA512";
        }
        this.sha256 = new SHA2.SHA256();

        try {
            this.treeHMac = Mac.getInstance(hmacAlgo, "SunJCE");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

        this.hmacBuf = new byte[msgDigestSize];
    }

    public void init(byte[] pkSeed) {
        final byte[] padding = new byte[bl];

        msgDigest.engineUpdate(pkSeed, 0, pkSeed.length);
        msgDigest.engineUpdate(padding, 0, bl - N); // toByte(0, 64 - n)
        msgMemo = msgDigest.clone();

        msgDigest.engineReset();

        sha256.engineUpdate(pkSeed, 0, pkSeed.length);
        sha256.engineUpdate(padding, 0, 64 - pkSeed.length); // toByte(0, 64 - n)
        sha256Memo = (SHA2.SHA256) sha256.clone();

        sha256.engineReset();
    }

    public JavaSha2Engine clone() {
        JavaSha2Engine clone = new JavaSha2Engine(robust, N, WOTS_W, D, A, K, H);
        clone.msgMemo = this.msgMemo;
        clone.sha256Memo = this.sha256Memo;
        return clone;
    }

    @Override
    protected byte[] calculateSha256Digest(int N, byte[]... data) {
        sha256.engineReset();
        return calculateSha256DigestWithoutReset(N, data);
    }

    private byte[] calculateSha256DigestWithoutReset(int N, byte[][] data) {
        for (byte[] d : data) {
            sha256.engineUpdate(d, 0, d.length);
        }
        byte[] out = new byte[N];
        sha256.implDigest(out, 0, N);
        return out;
    }

    @Override
    protected byte[] calculateSha256DigestFromMemo(int N, byte[]... data) {
        sha256.resetTo(sha256Memo);
        return calculateSha256DigestWithoutReset(N, data);
    }

    @Override
    protected byte[] calculateMsgDigest(int N, byte[]... data) {
        msgDigest.engineReset();
        return calculateMsgDigestWithoutReset(N, data);
    }

    private byte[] calculateMsgDigestWithoutReset(int N, byte[][] data) {
        for (byte[] d : data) {
            msgDigest.engineUpdate(d, 0, d.length);
        }
        byte[] out = new byte[N];
        msgDigest.implDigest(out, 0, N);
        return out;
    }

    @Override
    protected byte[] calculateMsgDigest(byte[]... data) {
        return this.calculateMsgDigest(this.msgDigestSize, data);
    }

    @Override
    protected byte[] calculateMsgDigestFromMemo(int N, byte[]... data) {
        msgDigest.resetTo(msgMemo);
        return calculateMsgDigestWithoutReset(N, data);
    }

    @Override
    public byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message) {
        SecretKeySpec keySpec = new SecretKeySpec(prf, this.hmacAlgo);
        try {
            treeHMac.init(keySpec);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        treeHMac.update(randomiser, 0, randomiser.length);
        treeHMac.update(message, 0, message.length);
        try {
            treeHMac.doFinal(hmacBuf, 0);
        } catch (ShortBufferException e) {
            throw new RuntimeException(e);
        }

        return Arrays.copyOfRange(hmacBuf, 0, N);
    }

    @Override
    protected void mgf1GenerateMask(byte[] buf, byte[] key) {
        mgf1(msgDigest, msgDigestSize, buf, key);
    }

    @Override
    protected void mgf1GenerateMask256(byte[] buf, byte[] key) {
        mgf1(sha256, 32, buf, key);
    }

    private void mgf1(DigestBase msgDigest, int msgDigestSize, byte[] buf, byte[] key) {
        byte[] counter = new byte[4];

        int i = 0;
        for (; i < (buf.length / msgDigestSize); i++) {
            msgDigest.engineReset();
            MGF1Utils.ItoOSP(i, counter);
            msgDigest.engineUpdate(key, 0, key.length);
            msgDigest.engineUpdate(counter, 0, counter.length);
            msgDigest.implDigest(buf, i * msgDigestSize, msgDigestSize);
        }

        int l = buf.length % msgDigestSize;
        if (l > 0) {
            msgDigest.engineReset();
            MGF1Utils.ItoOSP(i, counter);
            msgDigest.engineUpdate(key, 0, key.length);
            msgDigest.engineUpdate(counter, 0, counter.length);

            // implDigest only supports digestLengths that are multiples of 4 (SHA256) and 8 (SHA512).
            int resolution = msgDigestSize / 8;
            if (l % resolution == 0) {
                msgDigest.implDigest(buf, i * msgDigestSize, buf.length % msgDigestSize);
            } else {
                int l2 = ((l / resolution) + 1) * resolution;
                byte[] t = new byte[l2];
                msgDigest.implDigest(t, 0, l2);
                System.arraycopy(t, 0, buf, i * msgDigestSize, l);
            }
        }

    }
}
