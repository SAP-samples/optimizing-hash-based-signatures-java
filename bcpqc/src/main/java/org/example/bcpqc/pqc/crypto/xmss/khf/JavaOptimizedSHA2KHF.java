package org.example.bcpqc.pqc.crypto.xmss.khf;

import org.example.bcpqc.pqc.crypto.xmss.PRFCacheHashMap;
import sun.security.provider.SHA2;

import static sun.security.provider.ByteArrayAccess.i2bBig;

public class JavaOptimizedSHA2KHF extends AbstractDigestKHF {
    private final int typeDiscriminatorLength;
    private final SHA2.SHA256 digest;
    private final byte[] HmsgTypeBuffer;
    private final PRFCacheHashMap<int[]> prfCache = new PRFCacheHashMap<>(int[].class);

    public JavaOptimizedSHA2KHF(int digestSize) {
        super(digestSize);

        if (digestSize == 24) {
            this.typeDiscriminatorLength = 4;
        } else {
            this.typeDiscriminatorLength = 32;
        }
        this.HmsgTypeBuffer = new byte[typeDiscriminatorLength];
        this.HmsgTypeBuffer[typeDiscriminatorLength - 1] = 2;

        this.digest = new SHA2.SHA256();
    }

    @Override
    protected byte[] coreDigest(int fixedValue, byte[] key, byte[] index) {
        int size = this.typeDiscriminatorLength + key.length + index.length;
        byte[] buffer = prepareBufferWithPadding(size);

        buffer[typeDiscriminatorLength - 1] = (byte) fixedValue;

        System.arraycopy(key, 0, buffer, this.typeDiscriminatorLength, key.length);
        System.arraycopy(index, 0, buffer, this.typeDiscriminatorLength + key.length, index.length);

        digest.implCompressMultiBlock(buffer, 0, buffer.length - 1);
        int[] digestState = digest.state;
        byte[] result = new byte[digestSize];
        i2bBig(digestState, 0, result, 0, digestSize);
        digest.engineReset();
        return result;

    }

    public static byte[] prepareBufferWithPadding(int size) {
        int bufSize;
        int blocks;
        if (size % 64 >= 56) {
            blocks = (size / 64) + 2;
        } else {
            blocks = size / 64 + 1;
        }
        bufSize = blocks * 64;
        byte[] buf = new byte[bufSize];
        buf[size] = (byte) 0x80;
        // Inputs are always small, we never need more than 2 bytes to encode the size
        buf[bufSize - 1] = (byte) ((size * 8) % 256);
        buf[bufSize - 2] = (byte) (((size * 8) / 256) % 256);
        return buf;
    }

    @Override
    public byte[] HMsg_internal(byte[] key, byte[] in) {
        this.digest.engineUpdate(HmsgTypeBuffer, 0, typeDiscriminatorLength);
        this.digest.engineUpdate(key, 0, key.length);
        this.digest.engineUpdate(in, 0, in.length);

        byte[] buf = new byte[digestSize];
        this.digest.implDigest(buf, 0, digestSize);
        this.digest.engineReset();

        return buf;

    }

    @Override
    public byte[] PRF_internal(byte[] key, byte[] address) {
        if (digestSize != 32) {
            return this.coreDigest(3, key, address);
        }

        int size = this.typeDiscriminatorLength + key.length + address.length;
        byte[] buffer = prepareBufferWithPadding(size);

        System.arraycopy(address, 0, buffer, typeDiscriminatorLength + key.length, address.length);

        int[] cachedState = prfCache.get(key);

        if (cachedState == null) {
            System.arraycopy(key, 0, buffer, typeDiscriminatorLength, key.length);
            buffer[typeDiscriminatorLength - 1] = 3;

            digest.implCompress(buffer, 0);

            int[] digestState = digest.state.clone();
            this.prfCache.add(key, digestState);
        } else {
            this.digest.state = cachedState.clone();
        }
        digest.implCompress(buffer, 64);

        int[] digestState = digest.state;
        byte[] result = new byte[digestSize];
        i2bBig(digestState, 0, result, 0, digestSize);
        this.digest.engineReset();

        return result;
    }

    @Override
    public SHA2 HMsg_consumeMessage(byte[] key, byte[] in) {
        this.digest.engineUpdate(HmsgTypeBuffer, 0, typeDiscriminatorLength);
        this.digest.engineUpdate(key, 0, key.length);
        this.digest.engineUpdate(in, 0, in.length);

        SHA2 state = this.digest.clone();
        this.digest.engineReset();
        return state;
    }

    @Override
    public byte[] HMsg_counter(Object state, byte[] counter) {
        if (!(state instanceof SHA2.SHA256)) {
            throw new IllegalArgumentException("Wrong state type provided");
        }
        SHA2 sha256 = ((SHA2.SHA256) state).clone();

        sha256.engineUpdate(counter, 0, counter.length);

        byte[] buf = new byte[digestSize];
        sha256.implDigest(buf, 0, digestSize);

        return buf;
    }
}
