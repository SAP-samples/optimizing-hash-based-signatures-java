package org.example.jnihash;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.UnpooledByteBufAllocator;

import static org.example.jnihash.JniHash.D_INTR;
import static org.example.jnihash.JniHash.D_LEAF;

public class JniShake {
    static {
        System.loadLibrary("native");
    }

    private ByteBuf inBuf;
    private ByteBuf outBuf;
    private int n;
    private boolean robust;
    private byte[] pk_seed;

    public JniShake() {
        // Will automatically allocate more memory, if needed.
        inBuf = UnpooledByteBufAllocator.DEFAULT.directBuffer(128);
        outBuf = UnpooledByteBufAllocator.DEFAULT.directBuffer(32);

        CleanerProvider.registerByteBufs(this, inBuf, outBuf);
    }

    public void deallocate() {
        this.inBuf.release();
        this.outBuf.release();
    }

    public native long shake256_context();

    public native void shake256_free(long ctx);

    public native void shake256_update(long ctx, byte[] data, int inOff, int length);

    public native void shake256_doFinal(long ctx, int digestLength, byte[] out, int outOff);

    // Fixed sizes for XMSS
    public void shake256_256_xmss(int fixedValue, byte[] key, byte[] in, byte[] digest) {
        this.inBuf.writeZero(31);
        this.inBuf.writeByte(fixedValue);
        this.inBuf.writeBytes(key);
        this.inBuf.writeBytes(in);

        this.shake256_unsafe(this.inBuf.memoryAddress(), this.inBuf.writerIndex(), this.outBuf.memoryAddress(), 32);

        this.outBuf.getBytes(0, digest, 0, 32);

        this.inBuf.clear();
    }

    public void shake256_192_xmss(int fixedValue, byte[] key, byte[] in, byte[] digest) {
        this.inBuf.writeZero(3);
        this.inBuf.writeByte(fixedValue);
        this.inBuf.writeBytes(key);
        this.inBuf.writeBytes(in);

        this.shake256_unsafe(this.inBuf.memoryAddress(), this.inBuf.writerIndex(), this.outBuf.memoryAddress(), 24);

        this.outBuf.getBytes(0, digest, 0, 24);

        this.inBuf.clear();
    }

    private native void shake256_unsafe(long inBufAddress, int inputLength, long outBufAddress, int digestSize);

    // Fixed sizes LMS

    /**
     * @param I      16 byte
     * @param q      4 byte
     * @param i      2 byte
     * @param j      1 byte
     * @param data   24/32 byte
     * @param digest 24/32 byte output
     */
    public void shake256_lms_ots_chain(byte[] I, int q, int i, int j, byte[] data, byte[] digest) {
        this.inBuf.writeBytes(I);
        this.inBuf.writeInt(q);
        this.inBuf.writeShort(i);
        this.inBuf.writeByte((byte) (j & 0xFF));
        this.inBuf.writeBytes(data);

        this.shake256_unsafe(this.inBuf.memoryAddress(), this.inBuf.writerIndex(), this.outBuf.memoryAddress(), digest.length);

        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();
    }

    /**
     * @param I      16 byte
     * @param r      4 byte
     * @param data   24/32 byte
     * @param digest 24/32 byte output
     */
    public void shake256_lms_tree_leaf(byte[] I, int r, byte[] data, byte[] digest) {
        this.inBuf.writeBytes(I);
        this.inBuf.writeInt(r);
        this.inBuf.writeShort(D_LEAF);
        this.inBuf.writeBytes(data);

        this.shake256_unsafe(this.inBuf.memoryAddress(), this.inBuf.writerIndex(), this.outBuf.memoryAddress(), digest.length);

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
    public void shake256_lms_tree_intermediate(byte[] I, int r, byte[] d1, byte[] d2, byte[] digest) {
        this.inBuf.writeBytes(I);
        this.inBuf.writeInt(r);
        this.inBuf.writeShort(D_INTR);
        this.inBuf.writeBytes(d1);
        this.inBuf.writeBytes(d2);


        this.shake256_unsafe(this.inBuf.memoryAddress(), this.inBuf.writerIndex(), this.outBuf.memoryAddress(), digest.length);

        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();
    }

    // SPHINCS+

    public void shake256_sphincs_init(byte[] pk_seed, int n, boolean robust) {
        this.n = n;
        this.robust = robust;
        this.pk_seed = pk_seed;
        this.shake256_sphincs_init_native(pk_seed, n, robust);
    }

    private native void shake256_sphincs_init_native(byte[] pk_seed, int n, boolean robust);

    public void shake256_sphincs_th(byte[] adrs, byte[] message, byte[] digest) {
        // Space for pk_seed
        this.inBuf.writerIndex(n);
        this.inBuf.writeBytes(adrs, 0, 32);
        this.inBuf.writeBytes(message);

        if (robust) {
            this.shake256_unsafe_with_seed_robust(inBuf.memoryAddress(), inBuf.writerIndex(), outBuf.memoryAddress(),
                    digest.length);
        } else {
            this.shake256_unsafe_with_seed(inBuf.memoryAddress(), inBuf.writerIndex(), outBuf.memoryAddress(),
                    digest.length);
        }

        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();
    }

    public void shake256_sphincs_prf(byte[] seed, byte[] adrs, byte[] digest) {
        // Space for pk_seed
        this.inBuf.writerIndex(n);
        this.inBuf.writeBytes(adrs);
        this.inBuf.writeBytes(seed);
        
        this.shake256_unsafe_with_seed(inBuf.memoryAddress(), inBuf.writerIndex(), outBuf.memoryAddress(), digest.length);
        
        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();
    }

    public void shake256_sphincs_prf_msg(byte[] sk_prf, byte[] opt_rand, byte[] m, byte[] digest) {
        this.inBuf.writeBytes(sk_prf);
        this.inBuf.writeBytes(opt_rand);
        this.inBuf.writeBytes(m);

        this.shake256_unsafe(this.inBuf.memoryAddress(), this.inBuf.writerIndex(), this.outBuf.memoryAddress(), digest.length);

        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();
    }

    public void shake256_h_msh(byte[] r, byte[] pk_root, byte[] msg, byte[] digest) {
        this.inBuf.writeBytes(r);
        this.inBuf.writeBytes(pk_seed);
        this.inBuf.writeBytes(pk_root);
        this.inBuf.writeBytes(msg);

        // digest.length may be greater than 32 here so ensure that buffer is large enough
        this.outBuf.ensureWritable(digest.length);

        this.shake256_unsafe(this.inBuf.memoryAddress(), this.inBuf.writerIndex(), this.outBuf.memoryAddress(), digest.length);

        this.outBuf.getBytes(0, digest);

        this.inBuf.clear();
    }

    private native void shake256_unsafe_with_seed(long inBufAddress, int inputLength, long outBufAddress,
            int digestSize);

    private native void shake256_unsafe_with_seed_robust(long inBufAddress, int inputLength, long outBufAddress,
            int digestSize);

    
}
