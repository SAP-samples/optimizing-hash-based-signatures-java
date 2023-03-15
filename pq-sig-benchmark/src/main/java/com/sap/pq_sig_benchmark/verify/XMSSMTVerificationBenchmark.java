package com.sap.pq_sig_benchmark.verify;

import java.security.spec.AlgorithmParameterSpec;

import org.example.bcpqc.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.openjdk.jmh.annotations.Param;

import com.sap.pq_sig_benchmark.Parameters;

public class XMSSMTVerificationBenchmark extends VerificationBenchmark {

	@Param({	
		// SHA2_256
		Parameters.XMSSMT_SHA2_20d2_256,
		Parameters.XMSSMT_SHA2_20d4_256,
		Parameters.XMSSMT_SHA2_40d2_256,
		Parameters.XMSSMT_SHA2_40d4_256,
		Parameters.XMSSMT_SHA2_40d8_256,
		Parameters.XMSSMT_SHA2_60d3_256,
		Parameters.XMSSMT_SHA2_60d6_256,
		Parameters.XMSSMT_SHA2_60d12_256,

		// SHA2_192
	    Parameters.XMSSMT_SHA2_20d2_192,
	    Parameters.XMSSMT_SHA2_20d4_192,
	    Parameters.XMSSMT_SHA2_40d2_192,
	    Parameters.XMSSMT_SHA2_40d4_192,
	    Parameters.XMSSMT_SHA2_40d8_192,
	    Parameters.XMSSMT_SHA2_60d3_192,
	    Parameters.XMSSMT_SHA2_60d6_192,
	    Parameters.XMSSMT_SHA2_60d12_192,

	    // SHAKE256_256
	    Parameters.XMSSMT_SHAKE256_20d2_256,
	    Parameters.XMSSMT_SHAKE256_20d4_256,
	    Parameters.XMSSMT_SHAKE256_40d2_256,
	    Parameters.XMSSMT_SHAKE256_40d4_256,
	    Parameters.XMSSMT_SHAKE256_40d8_256,
	    Parameters.XMSSMT_SHAKE256_60d3_256,
	    Parameters.XMSSMT_SHAKE256_60d6_256,
	    Parameters.XMSSMT_SHAKE256_60d12_256,

	    // SHAKE256_192
	    Parameters.XMSSMT_SHAKE256_20d2_192,
	    Parameters.XMSSMT_SHAKE256_20d4_192,
	    Parameters.XMSSMT_SHAKE256_40d2_192,
	    Parameters.XMSSMT_SHAKE256_40d4_192,
	    Parameters.XMSSMT_SHAKE256_40d8_192,
	    Parameters.XMSSMT_SHAKE256_60d3_192,
	    Parameters.XMSSMT_SHAKE256_60d6_192,
	    Parameters.XMSSMT_SHAKE256_60d12_192
	})
	String xmssmt_parameter;

	public XMSSMTVerificationBenchmark() {
		super("XMSSMT", PROVIDER);
	}

	@Override
	protected AlgorithmParameterSpec getParameterSpec() throws Exception {
		return (XMSSMTParameterSpec) XMSSMTParameterSpec.class.getField(this.xmssmt_parameter).get(null);

	}

	@Override
	protected String getSignatureAlgorithm() {
		return Parameters.getSignatureAlgorithmForXMSSMTParameter(this.xmssmt_parameter);
	}

	@Override
	protected String getParameter() {
		return this.xmssmt_parameter;
	}

}
