package org.example.jnihash;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.UnpooledByteBufAllocator;

public class JniHash {
    static final int D_LEAF = 0x8282;
    static final int D_INTR = 0x8383;

    static {
        System.loadLibrary("native");
    }

    private final ByteBuf inBuf;
    private final ByteBuf outBuf;


    public JniHash() {
        // Will automatically allocate more memory, if needed.
        // 128: Max. input length for XMSS (excl. message hashing)
        // 73: Max. amount of additional space for the SHA2 padding
        inBuf = UnpooledByteBufAllocator.DEFAULT.directBuffer(128 + 73);
        outBuf = UnpooledByteBufAllocator.DEFAULT.directBuffer(32);

        CleanerProvider.registerByteBufs(this, inBuf, outBuf);
    }

    /*
     * Basic functions
     */

    private static native void sha2_free_state(long state);

    public native byte[] sha2_context();

    public native void sha2_update(byte[] context, byte[] data, int inOff, int len);

    /*
     * XMSS specific input sizes
     */

    public native int sha2_256_doFinal(byte[] context, byte[] out, int outOff);

    // We require the inBuf to be large enough to fit the next block as well. A
    // buffer that is
    // inLength + 9 + 64 bytes always fulfills this requirement.
    private native void sha2_unsafe(long inBufAddress, int inLength, long outBufAddress);

    public void sha2_xmss(byte fixedValue, int fixedValueLength, byte[] key, byte[] in, byte[] digest) {
        this.inBuf.writeZero(fixedValueLength - 1);
        this.inBuf.writeByte(fixedValue);
        this.inBuf.writeBytes(key);
        this.inBuf.writeBytes(in);

        this.inBuf.ensureWritable(this.inBuf.writerIndex() + 73);

        this.sha2_unsafe(this.inBuf.memoryAddress(), this.inBuf.writerIndex(), this.outBuf.memoryAddress());

        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();
    }

    public void sha2_xmss_fixed_padding(int fixedValue, int fixedValueLength, int fixedSizeIndex, byte[] key, byte[] in, byte[] digest) {
        this.inBuf.writeZero(fixedValueLength - 1);
        this.inBuf.writeByte(fixedValue);
        this.inBuf.writeBytes(key);
        this.inBuf.writeBytes(in);

        this.sha2_unsafe_fixed_padding(this.inBuf.memoryAddress(), fixedSizeIndex, this.outBuf.memoryAddress());

        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();
    }

    private native void sha2_unsafe_fixed_padding(long inBufAddress, int fixedSizeIndex, long outBufAddress);

    public IntermediateState sha2_256_xmss_prf_first_block(byte[] key) {
        this.inBuf.writeZero(31);
        this.inBuf.writeByte((byte) 3);
        this.inBuf.writeBytes(key, 0, 32);

        long address = this.sha2_intermediate_state(this.inBuf.memoryAddress(), this.inBuf.writerIndex());

        this.inBuf.clear();
        return new IntermediateState(address);
    }

    private native long sha2_intermediate_state(long inBufAddress, int inLength);

    public void sha2_256_768_lastBlock(IntermediateState intermediateState, byte[] data, byte[] digest) {
        this.inBuf.writeBytes(data, 0, 32);
        this.sha2_256_768_lastBlock(intermediateState.address, this.inBuf.memoryAddress(), this.outBuf.memoryAddress());
        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();
    }

    private native void sha2_256_768_lastBlock(long fromState, long inBufAddress, long outBufAddress);

    public void sha2_free_state(IntermediateState intermediateState) {
        sha2_free_state(intermediateState.address);
    }

    /**
     * @param I      16 byte
     * @param q      4 byte
     * @param i      2 byte
     * @param j      1 byte
     * @param data   24/32 byte
     * @param digest 24/32 byte output
     */
    public void sha2_lms_ots_chain(byte[] I, int q, int i, int j, byte[] data, byte[] digest) {
        this.inBuf.writeBytes(I);
        this.inBuf.writeInt(q);
        this.inBuf.writeShort(i);
        this.inBuf.writeByte((byte) (j & 0xFF));
        this.inBuf.writeBytes(data);

        this.sha2_unsafe(this.inBuf.memoryAddress(), this.inBuf.writerIndex(), this.outBuf.memoryAddress());

        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();
    }


    /*
     * LMS specific input sizes
     */

    public void sha2_lms_ots_chain_fixed_padding(byte[] I, int q, int i, int j, byte[] data, int fixedSizeIndex, byte[] digest) {
        this.inBuf.writeBytes(I);
        this.inBuf.writeInt(q);
        this.inBuf.writeShort(i);

        this.inBuf.writeByte((byte) (j & 0xFF));
        this.inBuf.writeBytes(data);

        this.sha2_unsafe_fixed_padding(this.inBuf.memoryAddress(), fixedSizeIndex, this.outBuf.memoryAddress());

        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();

    }

    /**
     * @param I      16 byte
     * @param r      4 byte
     * @param data   24/32 byte
     * @param digest 24/32 byte output
     */
    public void sha2_lms_tree_leaf(byte[] I, int r, byte[] data, byte[] digest) {
        this.inBuf.writeBytes(I);
        this.inBuf.writeInt(r);
        this.inBuf.writeShort(D_LEAF);
        this.inBuf.writeBytes(data);

        this.sha2_unsafe(this.inBuf.memoryAddress(), this.inBuf.writerIndex(), this.outBuf.memoryAddress());

        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();
    }

    public void sha2_lms_tree_leaf_fixed_padding(byte[] I, int r, byte[] data, int fixedSizeIndex, byte[] digest) {
        this.inBuf.writeBytes(I);
        this.inBuf.writeInt(r);
        this.inBuf.writeShort(D_LEAF);
        this.inBuf.writeBytes(data);

        this.sha2_unsafe_fixed_padding(this.inBuf.memoryAddress(), fixedSizeIndex, this.outBuf.memoryAddress());

        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();
    }

    /**
     * @param I      16 byte
     * @param r      4 byte
     * @param d1     24/32 byte
     * @param d2     24/32 byte
     * @param digest 24/32 byte output
     */
    public void sha2_lms_tree_intermediate(byte[] I, int r, byte[] d1, byte[] d2, byte[] digest) {
        this.inBuf.writeBytes(I);
        this.inBuf.writeInt(r);
        this.inBuf.writeShort(D_INTR);
        this.inBuf.writeBytes(d1);
        this.inBuf.writeBytes(d2);


        this.sha2_unsafe(this.inBuf.memoryAddress(), this.inBuf.writerIndex(), this.outBuf.memoryAddress());

        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();
    }

    public void sha2_lms_tree_intermediate_fixed_padding(byte[] I, int r, byte[] d1, byte[] d2, int fixedSizeIndex,
                                                         byte[] digest) {
        this.inBuf.writeBytes(I);
        this.inBuf.writeInt(r);
        this.inBuf.writeShort(D_INTR);
        this.inBuf.writeBytes(d1);
        this.inBuf.writeBytes(d2);


        this.sha2_unsafe_fixed_padding(this.inBuf.memoryAddress(), fixedSizeIndex, this.outBuf.memoryAddress());

        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();

    }

    // For XMSS SHA2_256 PRF Caching
    public class IntermediateState {
        long address;

        public IntermediateState(long address) {
            this.address = address;
            CleanerProvider.getCleaner().register(this, () -> JniHash.sha2_free_state(address));
        }
    }
}
