package org.example;

import java.nio.ByteBuffer;

public class JniTransfer {
    static {
        String path = System.getProperty("user.dir") + "/target/libbenchmark.so";
        System.load(path);
    }

    public native void testByteArrayElements(byte[] in, byte[] out);

    public native void testByteArrayCritical(byte[] in, byte[] out);

    public native void testByteArrayRegion(byte[] in, byte[] out);

    public native void testByteBuffer(ByteBuffer in, ByteBuffer out);

    public native void testUnsafe(long in, long out);

}
