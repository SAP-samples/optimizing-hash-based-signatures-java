package com.sap.pq_sig_benchmark.keygen;

import java.security.*;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import com.sap.pq_sig_benchmark.PQBenchmark;

@State(Scope.Thread)
public abstract class KeyGenerationBenchmark extends PQBenchmark {
	KeyPairGenerator kpg;
	KeyPair kp;

	@Param({"true", "false"})
	boolean zzz_parallel;

	@Param({"bc", "bc-optimized", "corretto", "jni", "jni-fixed-padding", "jni-prf-cache", "java", "java-optimized"})
	String hashingProvider;

	public KeyGenerationBenchmark(String provider) {
		super(provider);
	}

	@Setup(Level.Iteration)
	public void setUpBenchmarkAndHashing() throws Exception {
		setHashingProvider(hashingProvider, zzz_parallel);
		setUp();
	}


	public abstract void setUp() throws Exception;
	

	@Benchmark
	@BenchmarkMode(Mode.AverageTime)
	public Object testMethod() throws Exception {
        this.kp = this.kpg.generateKeyPair();
		return null;
	}
	
	@TearDown(Level.Trial)
	public void printKeySize() {
		if(this.kp.getPublic().getEncoded() == null || this.kp.getPrivate().getEncoded() == null){
			System.out.println("\nKey serialization not supported");
			return;
		}
		int privKeySize = this.kp.getPrivate().getEncoded().length;
		int pubKeySize = this.kp.getPublic().getEncoded().length;
		
		System.out.println();
		System.out.println("Private key size: " + privKeySize);
		System.out.println("Public key size: " + pubKeySize);
	}

}
