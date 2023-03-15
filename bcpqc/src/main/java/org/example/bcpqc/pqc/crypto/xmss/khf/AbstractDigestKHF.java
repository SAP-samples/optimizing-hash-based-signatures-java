package org.example.bcpqc.pqc.crypto.xmss.khf;

import org.example.bcpqc.pqc.crypto.xmss.DigestUtil;

/**
 * Crypto functions for XMSS.
 */
public abstract class AbstractDigestKHF extends KeyedHashFunctions {
    protected final int paddingSize;

    protected AbstractDigestKHF(int digestSize) {
        super(digestSize);
        this.paddingSize = DigestUtil.getPaddingSize(digestSize);
    }

    protected abstract byte[] coreDigest(int fixedValue, byte[] key, byte[] index);

    protected byte[] F_internal(byte[] key, byte[] in) {
        return coreDigest(0, key, in);
    }

    @Override
    public byte[] H_internal(byte[] key, byte[] in) {
        return coreDigest(1, key, in);
    }

    @Override
    public byte[] HMsg_internal(byte[] key, byte[] in) {
        return coreDigest(2, key, in);
    }

    @Override
    public byte[] PRF_internal(byte[] key, byte[] address) {
        return coreDigest(3, key, address);
    }

    @Override
    public Object HMsg_consumeMessage(byte[] key, byte[] in) {
        throw new RuntimeException("HMsg with state not supported");
    }

    @Override
    public byte[] HMsg_counter(Object state, byte[] counter) {
        throw new RuntimeException("HMsg with state not supported");
    }
}
