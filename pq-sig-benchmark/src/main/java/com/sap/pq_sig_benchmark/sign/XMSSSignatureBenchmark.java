package com.sap.pq_sig_benchmark.sign;

import java.security.spec.AlgorithmParameterSpec;

import org.example.bcpqc.pqc.jcajce.spec.XMSSParameterSpec;
import org.openjdk.jmh.annotations.Param;

import com.sap.pq_sig_benchmark.Parameters;

public class XMSSSignatureBenchmark extends SignatureBenchmark {
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
	String xmss_parameter;

	public XMSSSignatureBenchmark() {
		super("XMSS", PROVIDER);
	}
	
	public XMSSSignatureBenchmark(String xmss_parameter) {
		super("XMSS", PROVIDER);
		this.xmss_parameter = xmss_parameter;
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
