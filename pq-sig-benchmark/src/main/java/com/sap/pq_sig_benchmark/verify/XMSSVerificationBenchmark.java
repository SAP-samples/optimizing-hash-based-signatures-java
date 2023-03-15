package com.sap.pq_sig_benchmark.verify;

import java.security.spec.AlgorithmParameterSpec;

import org.example.bcpqc.pqc.jcajce.spec.XMSSParameterSpec;
import org.openjdk.jmh.annotations.Param;

import com.sap.pq_sig_benchmark.Parameters;

public class XMSSVerificationBenchmark extends VerificationBenchmark {

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

	public XMSSVerificationBenchmark() {
		super("XMSS", PROVIDER);
	}

	protected AlgorithmParameterSpec getParameterSpec() throws Exception {
		return (XMSSParameterSpec) XMSSParameterSpec.class.getField(this.xmss_parameter).get(null);
	}
	
	protected String getParameter() {
		return this.xmss_parameter;
	}
		
	protected String getSignatureAlgorithm() {
		return Parameters.getSignatureAlgorithmForXMSSParameter(this.xmss_parameter);
	}
}
