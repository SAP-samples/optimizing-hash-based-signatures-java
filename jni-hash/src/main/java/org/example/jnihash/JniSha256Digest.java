package org.example.jnihash;

import org.bouncycastle.crypto.Digest;

public class JniSha256Digest implements Digest {
    private final JniHash jniHash;
    private byte[] context;

    public JniSha256Digest() {
        this.jniHash = new JniHash();
        this.context = jniHash.sha2_context();
    }

    public JniSha256Digest(byte[] context) {
        this.context = context;
        this.jniHash = new JniHash();
    }

    public byte[] getContext() {
        return context;
    }

    public void setContext(byte[] context) {
        this.context = context;
    }

    @Override
    public String getAlgorithmName() {
        return "SHA-256";
    }

    @Override
    public int getDigestSize() {
        return 32;
    }

    @Override
    public void update(byte in) {
        byte[] i = {in};
        this.update(i, 0, 1);
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        this.jniHash.sha2_update(this.context, in, inOff, len);
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
        int r = this.jniHash.sha2_256_doFinal(context, out, outOff);
        this.reset();
        return r;
    }

    @Override
    public void reset() {
        this.context = jniHash.sha2_context();
    }

}
