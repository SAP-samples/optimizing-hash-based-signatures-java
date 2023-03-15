package com.sap.pq_sig_benchmark.wots.wotsplusc;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.example.bcpqc.experiments.hashing.HashingProviderProvider;
import org.example.bcpqc.pqc.crypto.xmss.*;
import org.example.bcpqc.pqc.crypto.xmss.khf.KeyedHashFunctions;
import org.openjdk.jmh.annotations.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public abstract class WOTSPlusCBenchmark {
    @Param({"32"})
    int digestSize;

    @Param("java-optimized")
    String hashingProvider;


    long[] counters;
    int i = 0;
    KeyedHashFunctions keyedHashFunctions;
    private WOTSPlusC wotsPlusC;
    private OTSHashAddress otsHashAddress;
    private byte[] keyHMsg;
    private byte[] msg;
    private WOTSPlusCtrSignature sig;
    private Path resultsFile;

    @Setup(Level.Trial)
    public void setUp() {
        HashingProviderProvider.setHashingProvider(hashingProvider);

        counters = new long[getWarmupIterations() + (1 << 10)];
        i = 0;

        this.otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().build();
        WOTSPlusCParameters wotsPlusCParameters = new WOTSPlusCParameters(NISTObjectIdentifiers.id_sha256, digestSize, getWotsPlusCSum(), 0, getWinternitzParameter());
        wotsPlusC = new WOTSPlusC(wotsPlusCParameters);
        keyHMsg = new byte[3 * digestSize];

        keyedHashFunctions = HashingProviderProvider.getHashingProvider().newKHF(NISTObjectIdentifiers.id_sha256, digestSize);

        resultsFile = Path.of("wotsplus-" + getWinternitzParameter() + "-results.txt");
        File f = new File(resultsFile.toUri());
        if (!f.exists()) {
            try {
                f.createNewFile();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    protected abstract int getWinternitzParameter();

    @Setup(Level.Iteration)
    public void setupIteration() {
        // Generate a "pseudo-random" message to sign
        msg = keyedHashFunctions.HMsg(keyHMsg, XMSSUtil.toBytesBigEndian(i - getWarmupIterations(), 32));
    }

    @Benchmark
    public void benchmark() {
        this.sig = wotsPlusC.signMessage(keyHMsg, msg, otsHashAddress);
    }

    @TearDown(Level.Iteration)
    public void collectResults() {
        this.counters[i] = sig.getCtr();
        i++;
    }


    @TearDown(Level.Trial)
    public void saveResults() {
        long[] results = Arrays.copyOfRange(this.counters, getWarmupIterations(), i);
        System.out.println(Arrays.toString(results));

        String r = getWotsPlusCSum() + ", " + Arrays.stream(results).mapToObj(Long::toString).collect(Collectors.joining(", ")) + "\n";
        try {
            Files.writeString(resultsFile, r, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    abstract int getWotsPlusCSum();

    abstract int getWarmupIterations();



}
