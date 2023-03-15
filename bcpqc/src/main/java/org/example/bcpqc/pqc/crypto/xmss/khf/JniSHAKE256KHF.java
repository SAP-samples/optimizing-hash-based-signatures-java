package org.example.bcpqc.pqc.crypto.xmss.khf;

import org.example.jnihash.JniShake;
import org.example.jnihash.JniShake256Digest;

public class JniSHAKE256KHF extends BCDigestKHF {
    private final JniShake jniShake;

    public JniSHAKE256KHF(int digestSize) {
        super(new JniShake256Digest(), digestSize);
        this.jniShake = new JniShake();
    }

    @Override
    public byte[] F_internal(byte[] key, byte[] in) {
        if (digestSize == 32) {
            byte[] out = new byte[32];
            jniShake.shake256_256_xmss(0, key, in, out);
            return out;
        } else {
            byte[] out = new byte[24];
            jniShake.shake256_192_xmss(0, key, in, out);
            return out;
        }
    }

    @Override
    public byte[] H_internal(byte[] key, byte[] in) {
        if (digestSize == 32) {
            byte[] out = new byte[32];
            jniShake.shake256_256_xmss(1, key, in, out);
            return out;
        } else {
            byte[] out = new byte[24];
            jniShake.shake256_192_xmss(1, key, in, out);
            return out;
        }
    }

    @Override
    public byte[] PRF_internal(byte[] key, byte[] address) {
        if (digestSize == 32) {
            byte[] out = new byte[32];
            jniShake.shake256_256_xmss(3, key, address, out);
            return out;
        } else {
            byte[] out = new byte[24];
            jniShake.shake256_192_xmss(3, key, address, out);
            return out;
        }
    }
}
