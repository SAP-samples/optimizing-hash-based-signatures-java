package com.sap.pq_sig_benchmark.keygen;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.example.bcpqc.experiments.hashing.HashingProviderProvider;
import org.example.bcpqc.pqc.jcajce.spec.XMSSParameterSpec;
import org.openjdk.jmh.annotations.Param;

import com.sap.pq_sig_benchmark.Parameters;

public class XMSSKeyGenerationBenchmark extends KeyGenerationBenchmark {
	// I would have preferred to pass a reference to Parameters::XMSS_PARAMETERS but
	// due to Java limitations that's apparently not possible
	@Param({ Parameters.SHA2_10_256, Parameters.SHA2_16_256, Parameters.SHA2_20_256, 
		// RFC
		Parameters.SHAKE_10_256, Parameters.SHAKE_16_256, Parameters.SHAKE_20_256,
		Parameters.SHA2_10_512, Parameters.SHA2_16_512, Parameters.SHA2_20_512,
		Parameters.SHAKE_10_512, Parameters.SHAKE_16_512, Parameters.SHAKE_20_512,
		// NIST
		Parameters.SHA2_10_192, Parameters.SHA2_16_192, Parameters.SHA2_20_192,
		Parameters.SHAKE256_10_256, Parameters.SHAKE256_16_256, Parameters.SHAKE256_20_256,
		Parameters.SHAKE256_10_192, Parameters.SHAKE256_16_192,	Parameters.SHAKE256_20_192
	})
	public String xmss_parameter;

	public void setUp() throws GeneralSecurityException, IllegalArgumentException, IllegalAccessException,
			NoSuchFieldException, SecurityException {
		this.kpg = KeyPairGenerator.getInstance("XMSS", provider);
		XMSSParameterSpec parameterSpec = (XMSSParameterSpec) XMSSParameterSpec.class.getField(this.xmss_parameter)
				.get(null);
		this.kpg.initialize(parameterSpec, new SecureRandom());
	}
	
	public XMSSKeyGenerationBenchmark()  {
		super(PROVIDER);
	}
	

}
