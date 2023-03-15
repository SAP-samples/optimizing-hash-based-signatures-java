package com.sap.pq_sig_benchmark;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.sap.pq_sig_benchmark.hash.SPHINCSPlusHashBenchmark;
import com.sap.pq_sig_benchmark.hash.XMSSHashBenchmark;
import com.sap.pq_sig_benchmark.keygen.SPHINCSPlusKeyGenerationBenchmark;
import com.sap.pq_sig_benchmark.sign.SPHINCSPlusSignatureBenchmark;
import com.sap.pq_sig_benchmark.verify.XMSSVerificationBenchmark;
import org.example.bcpqc.crypto.digests.haraka.JavaIntrinsicHaraka256;
import org.example.bcpqc.crypto.digests.haraka.JavaIntrinsicHaraka512;
import org.example.bcpqc.crypto.digests.haraka.JavaIntrinsicHarakaS;
import org.openjdk.jmh.infra.Blackhole;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class Profile {
    public static void main(String[] args) throws Exception {
        xmssHash();
    }

    private static void sphincsKeyGen() throws Exception {
        SPHINCSPlusKeyGenerationBenchmark benchmark = new SPHINCSPlusKeyGenerationBenchmark();
        benchmark.setHashingProvider("bc", false);

        benchmark.sphincsplus_parameter = "sha2_256s";
        benchmark.setUp();

        for (int i = 0; i < 200; i++) {
            benchmark.testMethod();
        }

    }

    private static void sphincsSign() throws Exception {
        SPHINCSPlusSignatureBenchmark benchmark = new SPHINCSPlusSignatureBenchmark();
        benchmark.setHashingProvider("bc", false);

        benchmark.sphincsplus_parameter = "sha2_256f";
        benchmark.setUp();

        for (int i = 0; i < 200; i++) {
            benchmark.sign();
        }

    }

    private static void sphincsHash() throws Exception {
        SPHINCSPlusHashBenchmark benchmark = new SPHINCSPlusHashBenchmark();

        benchmark.digestName = "Haraka";
        benchmark.hashingProvider = "jni";
        benchmark.paramSize = 32;
        benchmark.robust = false;
        benchmark.setup();

        for (int i = 0; i < 1000000000; i++) {
            benchmark.benchmark();
        }

    }

    private static void xmssHash() throws Exception {
        XMSSHashBenchmark benchmark = new XMSSHashBenchmark();


        benchmark.digestName = "SHA-256";
        benchmark.hashingProvider = "jni";
        benchmark.paramSize = 24;
        benchmark.setup();

        for (int i = 0; i < 1000000; i++) {
            benchmark.benchmark();
        }

    }


    private static byte[] haraka512Hash() {
        byte[] data = new byte[32];
        byte[] out = null;
        JavaIntrinsicHarakaS harakaS = new JavaIntrinsicHarakaS();
        //JavaIntrinsicHaraka256 haraka256 = new JavaIntrinsicHaraka256(harakaS);
        JavaIntrinsicHaraka512 haraka512 = new JavaIntrinsicHaraka512(harakaS);

        for(int i = 0; i < 1000000000; i++) {
            haraka512.update(data, 0, 16);
            out = haraka512.digest(64);
            haraka512.reset();
        }
        return out;
    }

    public static MessageDigest hash_init() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(AmazonCorrettoCryptoProvider.INSTANCE);

        //return MessageDigest.getInstance("SHA-256");
        return MessageDigest.getInstance("SHA-256", AmazonCorrettoCryptoProvider.PROVIDER_NAME);
    }
}
