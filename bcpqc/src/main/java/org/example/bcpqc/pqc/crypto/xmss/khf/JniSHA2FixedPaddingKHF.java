package org.example.bcpqc.pqc.crypto.xmss.khf;

import org.example.jnihash.JniHash;
import org.example.jnihash.JniSha256Digest;

public class JniSHA2FixedPaddingKHF extends BCDigestKHF {

    static final int _480 = 4;
    private static final int _768 = 0;
    private static final int _1024 = 1;
    private static final int _416 = 2;
    private static final int _608 = 3;
    protected final JniHash jniHash;

    public JniSHA2FixedPaddingKHF(int digestSize) {
        super(new JniSha256Digest(), digestSize);
        this.jniHash = new JniHash();
    }

    @Override
    public byte[] PRF_internal(byte[] key, byte[] address) {
        if (digestSize == 32) {
            byte[] out = new byte[32];
            jniHash.sha2_xmss_fixed_padding(3, this.paddingSize, _768, key, address, out);
            return out;
        } else {
            byte[] out = new byte[24];
            jniHash.sha2_xmss_fixed_padding(3, this.paddingSize, _480, key, address, out);
            return out;
        }
    }

    @Override
    protected byte[] F_internal(byte[] key, byte[] in) {
        if (digestSize == 32) {
            byte[] out = new byte[32];
            jniHash.sha2_xmss_fixed_padding(0, this.paddingSize, _768, key, in, out);
            return out;
        } else {
            byte[] out = new byte[24];
            jniHash.sha2_xmss_fixed_padding(0, this.paddingSize, _416, key, in, out);
            return out;
        }
    }

    @Override
    public byte[] H_internal(byte[] key, byte[] in) {
        if (digestSize == 32) {
            byte[] out = new byte[32];
            jniHash.sha2_xmss_fixed_padding(1, this.paddingSize, _1024, key, in, out);
            return out;
        } else {
            byte[] out = new byte[24];
            jniHash.sha2_xmss_fixed_padding(1, this.paddingSize, _608, key, in, out);
            return out;
        }
    }
}
