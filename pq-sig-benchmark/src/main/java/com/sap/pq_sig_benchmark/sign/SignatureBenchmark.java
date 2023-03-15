package com.sap.pq_sig_benchmark.sign;

import com.sap.pq_sig_benchmark.util.KeyHelper;
import com.sap.pq_sig_benchmark.PQBenchmark;
import org.bouncycastle.util.Strings;
import org.openjdk.jmh.annotations.*;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@State(Scope.Thread)
public abstract class SignatureBenchmark extends PQBenchmark {

    KeyPair kp;
    protected Signature sig;
    byte[] messageSignature;
    private String type;

    @Param({"bc", "bc-optimized", "corretto", "jni", "jni-fixed-padding", "jni-prf-cache"})
    String hashingProvider;

    protected static final byte[] msg = Strings.toByteArray(
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.");

    protected SignatureBenchmark(String type, String provider) {
        super(provider);
        this.type = type;
    }

    @Setup(Level.Iteration)
    public void setUpBenchmarkAndHashing() throws Exception {
        setHashingProvider(hashingProvider, false);
        setUp();
    }
    public void setUp() throws Exception {
        System.out.print("Setting up... ");
        String keyPath = "keys/" + this.type + "/" + this.getParameter();

        KeyFactory keyFactory = KeyFactory.getInstance(this.type, provider);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(this.type, provider);
        AlgorithmParameterSpec parameterSpec = getParameterSpec();

        this.kp = KeyHelper.loadOrGenerateKeyPair(keyPath, keyFactory, kpg, parameterSpec, getNewKeyLambda());

        this.sig = Signature.getInstance(this.getSignatureAlgorithm(), provider);
        this.sig.initSign(this.kp.getPrivate());
        System.out.println("Setup done.");
    }

    protected abstract AlgorithmParameterSpec getParameterSpec() throws Exception;

    protected abstract String getSignatureAlgorithm();

    protected abstract String getParameter();

    protected Function<KeyPair, KeyPair> getNewKeyLambda() {
        return null;
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void sign() throws Exception {
        this.sig.update(msg);

        this.messageSignature = this.sig.sign();
    }


    @TearDown(Level.Trial)
    public void printSignatureSize() {
        System.out.println();
        System.out.println("Signature size: " + this.messageSignature.length);
    }

}
