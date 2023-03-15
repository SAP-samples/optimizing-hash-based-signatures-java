package com.sap.pq_sig_benchmark.hash;

import org.example.bcpqc.experiments.hashing.HashingProviderProvider;
import org.example.bcpqc.pqc.crypto.xmss.DigestUtil;
import org.example.bcpqc.pqc.crypto.xmss.khf.KeyedHashFunctions;
import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

@State(Scope.Thread)

public class XMSSHashBenchmark {
    @Param({"SHA-256", "SHAKE256"})
    public String digestName;

    @Param({"24", "32"})
    public int paramSize;

    @Param({"bc", "bc-optimized", "corretto", "jni", "jni-fixed-padding", "jni-prf-cache", "java", "java-optimized"})
    public String hashingProvider;

    KeyedHashFunctions khf;


    byte[] in1;
    byte[] in2;

    @Setup(Level.Iteration)
    public void setup() {
        HashingProviderProvider.setHashingProvider(hashingProvider);
        khf = HashingProviderProvider.getHashingProvider().newKHF(DigestUtil.getDigestOID(digestName), paramSize);

        in1 = new byte[paramSize];
        in2 = new byte[paramSize];
        for (int i = 0; i < paramSize; i++) {
            in1[i] = (byte) i;
            in2[i] = (byte) (i + 32);
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public byte[] benchmark() throws Exception {
        return khf.F(in1, in2);
    }
}
