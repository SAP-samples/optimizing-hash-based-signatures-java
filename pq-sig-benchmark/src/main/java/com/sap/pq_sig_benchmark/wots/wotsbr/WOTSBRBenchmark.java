package com.sap.pq_sig_benchmark.wots.wotsbr;

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
public abstract class WOTSBRBenchmark {
    @Param({"32"})
    int digestSize;

    @Param("java-optimized")
    String hashingProvider;
    int[] sums;
    int i = 0;
    KeyedHashFunctions keyedHashFunctions;
    @Param({"4", "16"})
    int winternitzParameter;
    private WOTSBR wotsbr;
    private OTSHashAddress otsHashAddress;
    private byte[] keyHMsg;
    private byte[] msg;
    private WOTSBRSignature sig;
    private Path resultsFile;

    @Setup(Level.Trial)
    public void setUp() {
        HashingProviderProvider.setHashingProvider(hashingProvider);

        sums = new int[getWarmupIterations() + (1 << 10)];
        i = 0;

        this.otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().build();
        WOTSBRParameters wotsbrParameters = new WOTSBRParameters(NISTObjectIdentifiers.id_sha256, digestSize, false, getWotsBrIterations(), false, winternitzParameter);
        wotsbr = new WOTSBR(wotsbrParameters);
        keyHMsg = new byte[3 * digestSize];

        keyedHashFunctions = HashingProviderProvider.getHashingProvider().newKHF(NISTObjectIdentifiers.id_sha256, digestSize);

        resultsFile = Path.of("wotsbr-" + winternitzParameter + "-results.txt");
        File f = new File(resultsFile.toUri());
        if (!f.exists()) {
            try {
                f.createNewFile();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

    }

    @Setup(Level.Iteration)
    public void setupIteration() {
        // Generate a "pseudo-random" message to sign. Always start at 0 for the measurement iterations
        msg = keyedHashFunctions.HMsg(keyHMsg, XMSSUtil.toBytesBigEndian(i - getWarmupIterations(), 32));
    }

    @Benchmark
    public void benchmark() {
        this.sig = wotsbr.signMessage(keyHMsg, msg, otsHashAddress);
    }

    @TearDown(Level.Iteration)
    public void collectResults() {
        this.sums[i] = sig.getMaxSum();
        i++;
    }


    @TearDown(Level.Trial)
    public void saveResults() {
        int[] results = Arrays.copyOfRange(this.sums, getWarmupIterations(), i);
        System.out.println(Arrays.toString(results));

        String r = getWotsBrIterations() + ", " + Arrays.stream(results).mapToObj(Integer::toString).collect(Collectors.joining(", ")) + "\n";
        try {
            Files.writeString(resultsFile, r, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    abstract int getWotsBrIterations();

    abstract int getWarmupIterations();


}
