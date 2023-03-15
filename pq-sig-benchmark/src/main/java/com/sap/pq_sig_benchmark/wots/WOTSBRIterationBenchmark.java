package com.sap.pq_sig_benchmark.wots;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.example.bcpqc.experiments.hashing.HashingProviderProvider;
import org.example.bcpqc.pqc.crypto.xmss.*;
import org.openjdk.jmh.annotations.*;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
public class WOTSBRIterationBenchmark {
    private static final byte[] msg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    private byte[] key;

    @Param({"32"})
    int digestSize;

    @Param("java-optimized")
    String hashingProvider;

    @Param({"false", "true"})
    boolean useOnePadding;

    @Param("2986487")
    int iterationsR;

    @Param({"true", "false"})
    boolean includeChecksum;

    private WOTSBR wotsbr;
    private OTSHashAddress otsHashAddress;

    private WOTSBRSignature sig;


    @Setup(Level.Iteration)
    public void setUp() {
        HashingProviderProvider.setHashingProvider(hashingProvider);
        WOTSBRParameters wotsbrParameters = new WOTSBRParameters(NISTObjectIdentifiers.id_sha256, digestSize, useOnePadding, iterationsR, includeChecksum, 16);
        this.wotsbr = new WOTSBR(wotsbrParameters);
        this.key = new byte[digestSize * 3];
        this.otsHashAddress  = (OTSHashAddress) new OTSHashAddress.Builder().build();

    }

    @Benchmark
    public Object sign() {
        this.sig = wotsbr.signMessage(key, msg, otsHashAddress);
        return sig;
    }

    @TearDown(Level.Iteration)
    public void tearDown() {
        System.out.print("ctr = " + this.sig.getCtr() + ". ");
    }

}
