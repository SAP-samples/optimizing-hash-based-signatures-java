package org.example;

import org.apache.commons.codec.binary.Hex;

public class Test {

    public static void main(String[] args) {

        JniTransferBenchmark benchmark = new JniTransferBenchmark();

        benchmark.setUp();

        byte[] r;

        r = benchmark.testByteArrayElements();
        System.out.println(Hex.encodeHexString(r));

        r = benchmark.testByteArrayCritical();
        System.out.println(Hex.encodeHexString(r));

        r = benchmark.testByteArrayRegion();
        System.out.println(Hex.encodeHexString(r));

        r = benchmark.testDirectByteBuffer();
        System.out.println(Hex.encodeHexString(r));

        r = benchmark.testDirectByteBuffer();
        System.out.println(Hex.encodeHexString(r));



        r = benchmark.testNettyPooledByteBuf();
        System.out.println(Hex.encodeHexString(r));

        r = benchmark.testNettyPooledByteBuf();
        System.out.println(Hex.encodeHexString(r));

        
        r = benchmark.testNettyUnpooledByteBuf();
        System.out.println(Hex.encodeHexString(r));

        benchmark.tearDown();
        benchmark.setUp();

        r = benchmark.testNettyUnpooledByteBuf();
        System.out.println(Hex.encodeHexString(r));
        

        r = benchmark.testUnsafe();
        System.out.println(Hex.encodeHexString(r));

        benchmark.tearDown();

    }
}
