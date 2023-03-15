package org.example.jnihash;

import org.bouncycastle.crypto.Xof;

public class JniShake256Digest implements Xof {
    private JniShake jniShake;
    private long ctx;

    private void init() {
        if (jniShake == null) {
            this.jniShake = new JniShake();
        }
        ctx = jniShake.shake256_context();
    }

    @Override
    public int doFinal(byte[] out, int outOff, int outLen) {
        doOutput(out, outOff, outLen);
        return 0;
    }

    @Override
    public int doOutput(byte[] out, int outOff, int outLen) {
        jniShake.shake256_doFinal(ctx, outLen, out, outOff);
        this.ctx = 0; // memory freed in C
        return 0;
    }

    @Override
    public int getByteLength() {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public String getAlgorithmName() {
        return "SHAKE256";
    }

    @Override
    public int getDigestSize() {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public void update(byte b) {
        byte[] d = {b};
        jniShake.shake256_update(ctx, d, 0, 1);
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        if(this.ctx == 0){
            init();
        }
        jniShake.shake256_update(ctx, in, inOff, len);
    }

    @Override
    public int doFinal(byte[] bytes, int outOff) {
        return doFinal(bytes, outOff, 32);
    }

    @Override
    public void reset() {
        jniShake.shake256_free(ctx);
        ctx = 0;
    }
}
