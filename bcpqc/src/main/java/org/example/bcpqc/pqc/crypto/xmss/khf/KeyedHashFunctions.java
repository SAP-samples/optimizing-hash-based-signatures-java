package org.example.bcpqc.pqc.crypto.xmss.khf;

public abstract class KeyedHashFunctions {
    protected final int digestSize;

    protected KeyedHashFunctions(int digestSize) {
        this.digestSize = digestSize;
    }

    protected abstract byte[] F_internal(byte[] key, byte[] in);

    protected abstract byte[] H_internal(byte[] key, byte[] in);

    protected abstract byte[] HMsg_internal(byte[] key, byte[] in);

    protected abstract byte[] PRF_internal(byte[] key, byte[] address);

    public abstract Object HMsg_consumeMessage(byte[] key, byte[] in);

    public abstract byte[] HMsg_counter(Object state, byte[] counter);

    public byte[] F(byte[] key, byte[] in) {
        if (key.length != digestSize) {
            throw new IllegalArgumentException("wrong key length");
        }
        if (in.length != digestSize) {
            throw new IllegalArgumentException("wrong in length");
        }
        return F_internal(key, in);
    }

    public byte[] H(byte[] key, byte[] in) {
        if (key.length != digestSize) {
            throw new IllegalArgumentException("wrong key length");
        }
        if (in.length != (2 * digestSize)) {
            throw new IllegalArgumentException("wrong in length");
        }
        return H_internal(key, in);
    }

    public byte[] HMsg(byte[] key, byte[] in) {
        if (key.length != (3 * digestSize)) {
            throw new IllegalArgumentException("wrong key length");
        }
        return HMsg_internal(key, in);
    }

    public byte[] PRF(byte[] key, byte[] address) {
        if (key.length != digestSize) {
            throw new IllegalArgumentException("wrong key length");
        }
        if (address.length != 32) {
            throw new IllegalArgumentException("wrong address length");
        }
        return PRF_internal(key, address);
    }

}
