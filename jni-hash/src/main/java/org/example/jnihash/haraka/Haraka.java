package org.example.jnihash.haraka;

import java.io.ByteArrayOutputStream;

public abstract class Haraka {
    static final int ROUNDS = 5;
    static final int AES_ROUNDS = 2;

    public static boolean hasNativeInstructions() {
        if (check_for_native_instructions() == 1)
            return true;
        return false;
    }

    public native void haraka256(long buffer);
    public native void haraka512(long buffer);

    public native void haraka512perm(long buffer);

    public native void load_constants();

    public native void set_constants(int[] in);
    public static native int check_for_native_instructions();

    /**
     * load methods from C library
     */
    static {
        // TODO change
        System.loadLibrary("native");
    }

    public Haraka() {
    }


    /**
     * single byte
     */
    public void update(byte b) {
        throw new RuntimeException("Not implemented");
    }

    /**
     * entire array
     *
     * @param bytes bytearray
     * @param i     offset
     * @param i1    length
     *              using ByteArrayOutputStream for convenience
     */
    public abstract void update(byte[] bytes, int offset, int length);

    public abstract void reset();
}
