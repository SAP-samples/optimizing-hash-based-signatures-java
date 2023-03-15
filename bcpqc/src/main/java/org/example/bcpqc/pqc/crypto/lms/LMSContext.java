package org.example.bcpqc.pqc.crypto.lms;


import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;



public class LMSContext
        implements Digest {
    private final byte[] C;
    private final LMOtsPrivateKey key;
    private final LMSigParameters sigParams;
    private final byte[][] path;
    private final LMOtsPublicKey publicKey;
    private final Object signature;

    private LMSSignedPubKey[] signedPubKeys;
    private volatile Digest digest;

    private int digestLength;

    public LMSContext(LMOtsPrivateKey key, LMSigParameters sigParams, Digest digest, byte[] C, byte[][] path) {
        this.key = key;
        this.sigParams = sigParams;
        this.digest = digest;
        this.C = C;
        this.path = path;
        this.publicKey = null;
        this.signature = null;
        this.digestLength = key.getParameter().getN();
    }

    public LMSContext(LMOtsPublicKey publicKey, Object signature, Digest digest) {
        this.publicKey = publicKey;
        this.signature = signature;
        this.digest = digest;
        this.C = null;
        this.key = null;
        this.sigParams = null;
        this.path = null;
        this.digestLength = publicKey.getParameter().getN();
    }

    byte[] getC() {
        return C;
    }

    byte[] getQ() {

        byte[] Q = new byte[digestLength + 2];

        this.doFinal(Q, 0);

        digest = null;

        return Q;
    }

    byte[][] getPath() {
        return path;
    }

    LMOtsPrivateKey getPrivateKey() {
        return key;
    }

    public LMOtsPublicKey getPublicKey() {
        return publicKey;
    }

    LMSigParameters getSigParams() {
        return sigParams;
    }

    public Object getSignature() {
        return signature;
    }

    LMSSignedPubKey[] getSignedPubKeys() {
        return signedPubKeys;
    }

    LMSContext withSignedPublicKeys(LMSSignedPubKey[] signedPubKeys) {
        this.signedPubKeys = signedPubKeys;

        return this;
    }

    public String getAlgorithmName() {
        return digest.getAlgorithmName();
    }

    public int getDigestSize() {
        return digest.getDigestSize();
    }

    public void update(byte in) {
        digest.update(in);
    }

    public void update(byte[] in, int inOff, int len) {
        digest.update(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff) {
        if (digest instanceof Xof) {
            return ((Xof) digest).doFinal(out, outOff, digestLength);
        } else if (digestLength < digest.getDigestSize()) {
            byte[] buf = new byte[digest.getDigestSize()];
            int r = digest.doFinal(buf, 0);
            System.arraycopy(buf, 0, out, outOff, digestLength);
            return r;
        } else {
            return digest.doFinal(out, outOff);
        }
    }

    public void reset() {
        digest.reset();
    }
}
