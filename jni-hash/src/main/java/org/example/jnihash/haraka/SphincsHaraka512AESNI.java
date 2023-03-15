package org.example.jnihash.haraka;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.UnpooledByteBufAllocator;
import org.example.jnihash.CleanerProvider;

public class SphincsHaraka512AESNI extends SphincsHaraka512 {
    private final ByteBuf buf;
    int[] rc;
    private int max = 0;

    public SphincsHaraka512AESNI() {
        this.rc = SphincsHarakaConst.roundConstants;
        load_constants();

        buf = UnpooledByteBufAllocator.DEFAULT.directBuffer(64);
        CleanerProvider.registerByteBufs(this, buf);
    }

    @Override
    public void update(byte[] bytes, int offset, int length) {
        buf.writeBytes(bytes, offset, length);
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
    public byte[] digest(int digestLength) {
        int index = this.buf.writerIndex();
        if (max > index) {
            this.buf.writeZero(max - index);
        }
        max = index;

        haraka512(this.buf.memoryAddress());

        byte[] out = new byte[digestLength];
        this.buf.getBytes(0, out);
        return out;
    }

    @Override
    public byte[] digest() {
        return digest(32);
    }

    /**
     * hand control to the C library to compute permutation
     *
     * @return computed digest
     */
    public byte[] permute(byte[] data) {
        this.buf.setBytes(0, data, 0, 64);
        haraka512perm(this.buf.memoryAddress());

        byte[] out = new byte[64];
        this.buf.getBytes(0, out);
        reset();
        return out;
    }

    @Override
    public int[] getConstants() {
        return this.rc;
    }

    public void setConstants(int[] in) {
        this.rc = in;
        set_constants(in);
    }

    public void deallocate() {
        this.buf.release();
    }

}
