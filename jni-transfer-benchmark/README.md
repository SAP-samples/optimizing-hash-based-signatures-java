# JNI Transfer Benchmark

Benchmarks transfer of data between Java and native code (JNI). It transfers 64 bytes of data from a byte array via JNI and performs a simple dummy task in native code which returns 32 bytes of data to the Java code. 

The project contains the following benchmark methods:

- ``testByteArrayElements``: Access the Java byte array using the JNI functions ``GetByteArrayElements``/``ReleaseByteArrayElements``
- ``testByteArrayCritical``: Access the Java byte array using the JNI functions ``GetPrimitiveArrayCritical``/``ReleasePrimitiveArrayCritical``
- ``testByteArrayRegion``: Access the Java byte array using the JNI functions ``GetByteArrayRegion``/``SetByteArrayRegion``
- ``testDirectByteBuffer``: Copy data to a Java direct ``ByteBuffer`` and retrieve its address in JNI using ``GetDirectBufferAddress``
- ``testNettyPooledByteBuf``: Copy data to a Netty pooled ``ByteBuf`` and pass its address to the native method
- ``testNettyUnpooledByteBuf``: Copy data to a Netty unpooled ``ByteBuf`` and pass its address to the native method
- ``testUnsafe``: Use the ``sun.misc.Unsafe`` class to allocate native memory, copy data to it and pass its address to the native method

For more details, please refer to the thesis this code accompanies.
