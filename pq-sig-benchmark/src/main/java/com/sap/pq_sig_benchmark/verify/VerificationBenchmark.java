package com.sap.pq_sig_benchmark.verify;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.util.Strings;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import com.sap.pq_sig_benchmark.util.KeyHelper;
import com.sap.pq_sig_benchmark.PQBenchmark;

@State(Scope.Thread)
public abstract class VerificationBenchmark extends PQBenchmark {
	protected KeyPair kp;
	protected Signature ver;
	protected byte[] messageSignature;
	private String type;

	private Signature sign;

	private static byte[] msg = Strings.toByteArray(
			"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.");

	@Param({"bc", "bc-optimized", "corretto", "jni", "jni-fixed-padding", "jni-prf-cache"})
	public String hashingProvider;

	protected VerificationBenchmark(String type, String provider) {
		super(provider);
		this.type = type;
	}

	@Setup(Level.Trial)
	public void setUp() throws Exception {
		setHashingProvider(hashingProvider, false);

		String keyPath = "keys/" + this.type + "/" + this.getParameter();

		KeyFactory keyFactory = KeyFactory.getInstance(this.type, provider);
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(this.type, provider);
		AlgorithmParameterSpec parameterSpec = getParameterSpec();

		this.kp = KeyHelper.loadOrGenerateKeyPair(keyPath, keyFactory, kpg, parameterSpec, null);

		this.sign = Signature.getInstance(this.getSignatureAlgorithm(), provider);
		this.sign.initSign(this.kp.getPrivate());
	}

	@Setup(Level.Iteration)
	public void setUpIteration() throws Exception {
		this.sign.update(msg);
		this.messageSignature = sign.sign();

		this.ver = Signature.getInstance(this.getSignatureAlgorithm(), provider);
		this.ver.initVerify(this.kp.getPublic());
	}


	protected abstract AlgorithmParameterSpec getParameterSpec() throws Exception;

	protected abstract String getSignatureAlgorithm();

	protected abstract String getParameter();

	@Benchmark
	@BenchmarkMode(Mode.AverageTime)
	@OutputTimeUnit(TimeUnit.MILLISECONDS)
	public void verify(Blackhole blackhole) throws Exception {
		this.ver.update(msg);
		boolean result = this.ver.verify(messageSignature);
		
		if(!result) throw new Exception("Verification failed");
		blackhole.consume(result);
	}

}
