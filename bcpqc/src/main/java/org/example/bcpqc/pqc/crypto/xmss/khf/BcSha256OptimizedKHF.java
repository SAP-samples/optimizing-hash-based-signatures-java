package org.example.bcpqc.pqc.crypto.xmss.khf;

import org.bouncycastle.util.Memoable;
import org.example.bcpqc.crypto.digests.SHA256Digest;
import org.example.bcpqc.pqc.crypto.xmss.DigestUtil;
import org.example.bcpqc.pqc.crypto.xmss.PRFCacheHashMap;

public class BcSha256OptimizedKHF extends KeyedHashFunctions {
    private final int paddingSize;
    private SHA256Digest digest;
    private final byte[] type = new byte[4];

    private final PRFCacheHashMap<byte[]> prfCache = new PRFCacheHashMap<>(byte[].class);

    public BcSha256OptimizedKHF(int digestSize) {
        super(digestSize);
        this.paddingSize = DigestUtil.getPaddingSize(digestSize);
        this.digest = new SHA256Digest();
    }

    private byte[] doFinal() {
        byte[] buffer = new byte[digest.getDigestSize()];
        digest.doFinal(buffer, 0);

        if (digestSize < digest.getDigestSize()) {
            byte[] out = new byte[digestSize];
            System.arraycopy(buffer, 0, out, 0, digestSize);
            return out;
        } else {
            return buffer;
        }

    }

    private void consumeType(int type) {
        if (paddingSize > 4) {
            digest.processZeroBytes(paddingSize - 4);
        }
        this.type[3] = (byte) type;
        digest.processMultipleWords(this.type);
    }

    @Override
    protected byte[] F_internal(byte[] key, byte[] in) {
        this.consumeType(0);
        digest.processMultipleWords(key);
        digest.processMultipleWords(in);
        return this.doFinal();
    }

    @Override
    protected byte[] H_internal(byte[] key, byte[] in) {
        this.consumeType(1);
        digest.processMultipleWords(key);
        digest.processMultipleWords(in);
        return this.doFinal();
    }

    @Override
    protected byte[] HMsg_internal(byte[] key, byte[] in) {
        this.consumeType(2);
        digest.processMultipleWords(key);
        digest.update(in, 0, in.length);
        return this.doFinal();
    }

    @Override
    protected byte[] PRF_internal(byte[] key, byte[] address) {
        if (digestSize == 32) {
            byte[] state = prfCache.get(key);
            if (state == null) {
                this.consumeType(3);
                digest.processMultipleWords(key);
                state = digest.getEncodedState();
                this.prfCache.add(key, state);
            } else {
                this.digest = new SHA256Digest(state);
            }
        } else {
            this.consumeType(3);
            digest.processMultipleWords(key);
        }

        digest.processMultipleWords(address);
        return this.doFinal();
    }

    @Override
    public Object HMsg_consumeMessage(byte[] key, byte[] in) {
        this.consumeType(2);
        digest.processMultipleWords(key);
        digest.update(in, 0, in.length);

        Memoable state = digest.copy();
        this.digest.reset();
        return state;
    }

    @Override
    public byte[] HMsg_counter(Object o, byte[] counter) {
        this.digest.reset((Memoable) o);
        digest.update(counter, 0, counter.length);
        return this.doFinal();
    }
}
