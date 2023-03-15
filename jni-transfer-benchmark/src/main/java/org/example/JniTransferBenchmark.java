package org.example;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.UnpooledByteBufAllocator;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import sun.misc.Unsafe;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@Measurement(iterations = 200, time = 100, timeUnit = TimeUnit.MILLISECONDS)
@Warmup(iterations = 10, time = 1, timeUnit = TimeUnit.SECONDS)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class JniTransferBenchmark {
    private static final int OUT_LENGTH = 32;
    private static final int IN_LENGTH = 64;

    private final JniTransfer jniTransfer = new JniTransfer();
    private final byte[] in = new byte[IN_LENGTH];
    private ByteBuffer inBuffer;
    private ByteBuffer outBuffer;

    private ByteBuf inNettyPooledBuf;
    private ByteBuf outNettyPooledBuf;

    private Unsafe unsafe;
    private long inUnsafeAddress;
    private long outUnsafeAddress;
    private long BYTE_ARRAY_BASE_OFFSET;
    private ByteBuf inNettyUnpooledBuf;
    private ByteBuf outNettyUnpooledBuf;

    @Setup(Level.Iteration)
    public void setUp() {
        for (int i = 0; i < in.length; i++) {
            in[i] = (byte) i;
        }

        this.inBuffer = ByteBuffer.allocateDirect(IN_LENGTH);
        this.outBuffer = ByteBuffer.allocateDirect(OUT_LENGTH);

        this.inNettyPooledBuf = PooledByteBufAllocator.DEFAULT.directBuffer(IN_LENGTH);
        this.outNettyPooledBuf = PooledByteBufAllocator.DEFAULT.directBuffer(OUT_LENGTH);

        this.inNettyUnpooledBuf = UnpooledByteBufAllocator.DEFAULT.directBuffer(IN_LENGTH);
        this.outNettyUnpooledBuf = UnpooledByteBufAllocator.DEFAULT.directBuffer(OUT_LENGTH);

        Field f;
        try {
            f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            unsafe = (Unsafe) f.get(null);    
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }

        this.inUnsafeAddress = unsafe.allocateMemory(IN_LENGTH);
        this.outUnsafeAddress = unsafe.allocateMemory(OUT_LENGTH);
        this.BYTE_ARRAY_BASE_OFFSET = unsafe.arrayBaseOffset(byte[].class);
    }

    @TearDown(Level.Iteration)
    public void tearDown() {

        this.inNettyPooledBuf.release();
        this.outNettyPooledBuf.release();

        this.inNettyUnpooledBuf.release();
        this.outNettyUnpooledBuf.release();

        this.unsafe.freeMemory(inUnsafeAddress);
        this.unsafe.freeMemory(outUnsafeAddress);
    }

    @Benchmark
    public byte[] testByteArrayElements() {
        byte[] buf = new byte[OUT_LENGTH];

        jniTransfer.testByteArrayElements(in, buf);

        return buf;
    }

    @Benchmark
    public byte[] testByteArrayCritical() {
        byte[] buf = new byte[OUT_LENGTH];

        jniTransfer.testByteArrayCritical(in, buf);

        return buf;
    }

    @Benchmark
    public byte[] testByteArrayRegion() {
        byte[] buf = new byte[OUT_LENGTH];

        jniTransfer.testByteArrayRegion(in, buf);

        return buf;
    }

    @Benchmark
    public byte[] testDirectByteBuffer() {
        inBuffer.clear();
        outBuffer.clear();

        inBuffer.put(in, 0, IN_LENGTH);

        jniTransfer.testByteBuffer(inBuffer, outBuffer);

        byte[] out = new byte[OUT_LENGTH];

        outBuffer.get(out, 0, OUT_LENGTH);

        return out;
    }

    @Benchmark
    public byte[] testNettyPooledByteBuf() {
        inNettyPooledBuf.clear();
        outNettyPooledBuf.clear();

        inNettyPooledBuf.setBytes(0, in);

        jniTransfer.testUnsafe(inNettyPooledBuf.memoryAddress(), outNettyPooledBuf.memoryAddress());

        byte[] out = new byte[OUT_LENGTH];
        outNettyPooledBuf.getBytes(0, out);
        

        return out;
    }

    @Benchmark
    public byte[] testNettyUnpooledByteBuf() {
        inNettyUnpooledBuf.clear();
        outNettyUnpooledBuf.clear();

        inNettyUnpooledBuf.setBytes(0, in);

        jniTransfer.testUnsafe(inNettyUnpooledBuf.memoryAddress(), outNettyUnpooledBuf.memoryAddress());

        byte[] out = new byte[OUT_LENGTH];
        outNettyUnpooledBuf.getBytes(0, out);
        
        return out;
    }


    /**
     * Disclaimer:
     * 
     * > Although, Unsafe has a bunch of useful applications, never use it.
     * 
     * http://mishadoff.com/blog/java-magic-part-4-sun-dot-misc-dot-unsafe/
     *
     * This code should not be used for any productive application.
     *
     */
    @Benchmark
    public byte[] testUnsafe() {
        unsafe.copyMemory(in, BYTE_ARRAY_BASE_OFFSET, null, inUnsafeAddress, IN_LENGTH);

        jniTransfer.testUnsafe(inUnsafeAddress, outUnsafeAddress);

        byte[] out = new byte[OUT_LENGTH];
        unsafe.copyMemory(null, outUnsafeAddress, out, this.BYTE_ARRAY_BASE_OFFSET, OUT_LENGTH);

        return out;
    }
}
