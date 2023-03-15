package com.sap.pq_sig_benchmark.hash;

import org.example.bcpqc.experiments.hashing.HashingProviderProvider;
import org.example.bcpqc.pqc.crypto.sphincsplus.ADRS;
import org.example.bcpqc.pqc.crypto.sphincsplus.SPHINCSPlusEngine;
import org.example.bcpqc.pqc.crypto.sphincsplus.SPHINCSPlusEngines;
import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
public class SPHINCSPlusHashBenchmark {
    @Param({"SHA-256"/*, "SHAKE256"*/})
    public String digestName;

    @Param({"16", "24", "32"})
    public int paramSize;

    @Param({"bc", /*"bc-optimized", "corretto", "jni", "jni-fixed-padding", "jni-prf-cache",*/ "java" /*, "java-optimized"*/})
    public String hashingProvider;

    @Param(/*"true",*/ "false")
    public boolean robust;
    SPHINCSPlusEngine engine;


    byte[] in1;
    byte[] in2;
    private ADRS adrs;

    @Setup(Level.Iteration)
    public void setup() {
        HashingProviderProvider.setHashingProvider(hashingProvider);
        SPHINCSPlusEngines sphincsPlusEngines = HashingProviderProvider.getHashingProvider().getSphincsPlusEngines();
        switch (this.digestName) {
            case "SHA-256" -> this.engine = sphincsPlusEngines.getSha2Engine(robust, paramSize, 16, 22, 6, 33, 66);
            case "SHAKE256" -> this.engine = sphincsPlusEngines.getShake256Engine(robust, paramSize, 16, 22, 6, 33, 66);
            case "Haraka" -> this.engine = sphincsPlusEngines.getHarakaSEngine(robust, paramSize, 16, 22, 6, 33, 66);
            default -> throw new IllegalArgumentException("Unknown digest");
        }

        adrs = new ADRS();

        in1 = new byte[paramSize];
        in2 = new byte[paramSize];
        for (int i = 0; i < paramSize; i++) {
            in1[i] = (byte) i;
            in2[i] = (byte) (i + 32);
        }

        engine.init(in1);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public byte[] benchmark() throws Exception {
        return engine.F(in1, adrs, in2);
    }

}
