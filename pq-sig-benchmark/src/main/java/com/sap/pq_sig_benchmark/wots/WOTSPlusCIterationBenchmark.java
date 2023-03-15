package com.sap.pq_sig_benchmark.wots;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.example.bcpqc.experiments.hashing.HashingProviderProvider;
import org.example.bcpqc.pqc.crypto.xmss.OTSHashAddress;
import org.example.bcpqc.pqc.crypto.xmss.WOTSPlusC;
import org.example.bcpqc.pqc.crypto.xmss.WOTSPlusCParameters;
import org.example.bcpqc.pqc.crypto.xmss.WOTSPlusCtrSignature;
import org.openjdk.jmh.annotations.*;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
public class WOTSPlusCIterationBenchmark {
    private static final byte[] msg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    private byte[] key;

    @Param({"650"})
    int sum;
    @Param({"32"})
    int digestSize;

    @Param("0")
    int zeroBlocks;

    @Param("java-optimized")
    String hashingProvider;

    private WOTSPlusC wotsPlusC;
    private OTSHashAddress otsHashAddress;

    private WOTSPlusCtrSignature sig;

    @Setup(Level.Iteration)
    public void setUp() {
        HashingProviderProvider.setHashingProvider(hashingProvider);
        WOTSPlusCParameters wotsPlusCParameters = new WOTSPlusCParameters(NISTObjectIdentifiers.id_sha256, digestSize, sum, zeroBlocks, 16);
        this.wotsPlusC = new WOTSPlusC(wotsPlusCParameters);
        this.key = new byte[digestSize * 3];
        this.otsHashAddress  = (OTSHashAddress) new OTSHashAddress.Builder().build();

    }

    @Benchmark
    public Object sign() {
        this.sig = wotsPlusC.signMessage(key, msg, otsHashAddress);
        return sig;
    }

    @TearDown(Level.Iteration)
    public void tearDown() {
        System.out.print("ctr = " + this.sig.getCtr() + ". ");
    }


}
