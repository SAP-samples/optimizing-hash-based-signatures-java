package org.example.jnihash.haraka;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.UnpooledByteBufAllocator;
import org.example.jnihash.CleanerProvider;

public class SphincsHaraka256AESNI extends SphincsHaraka256 {
    private final ByteBuf buf;
    int[] rc;
    private int max = 0;

    public SphincsHaraka256AESNI() {
        load_constants();

        buf = UnpooledByteBufAllocator.DEFAULT.directBuffer(32);
        CleanerProvider.registerByteBufs(this, buf);
    }

    @Override
    public void update(byte[] bytes, int offset, int length) {
        this.buf.writeBytes(bytes);
    }

    @Override
    public void reset() {
        this.buf.clear();
    }

    /**
     * hand control to the C library to compute digest
     *
     * @return computed digest
     */
    public byte[] digest() {
        int index = this.buf.writerIndex();
        if (max > index) {
            this.buf.writeZero(max - index);
        }
        max = index;

        byte[] digest = new byte[32];
        haraka256(this.buf.memoryAddress());
        this.buf.getBytes(0, digest);
        return digest;
    }

    @Override
    public int[] getConstants() {
        return this.rc;
    }

    public void setConstants(int[] in) {
        this.rc = in;
        set_constants(in);
    }

}


