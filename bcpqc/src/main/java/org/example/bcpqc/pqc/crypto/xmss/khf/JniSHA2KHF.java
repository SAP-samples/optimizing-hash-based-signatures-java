package org.example.bcpqc.pqc.crypto.xmss.khf;

import org.example.jnihash.JniHash;
import org.example.jnihash.JniSha256Digest;

public class JniSHA2KHF extends BCDigestKHF {

    private final JniHash jniHash;

    public JniSHA2KHF(int digestSize) {
        super(new JniSha256Digest(), digestSize);
        jniHash = new JniHash();
    }

    @Override
    public byte[] F_internal(byte[] key, byte[] in) {
        byte[] out = new byte[digestSize];
        jniHash.sha2_xmss((byte) 0, this.paddingSize, key, in, out);
        return out;
    }

    @Override
    public byte[] H_internal(byte[] key, byte[] in) {
        byte[] out = new byte[digestSize];
        jniHash.sha2_xmss((byte) 1, this.paddingSize, key, in, out);
        return out;
    }

    @Override
    public byte[] PRF_internal(byte[] key, byte[] address) {
        byte[] out = new byte[digestSize];
        jniHash.sha2_xmss((byte) 3, this.paddingSize, key, address, out);
        return out;
    }
}
