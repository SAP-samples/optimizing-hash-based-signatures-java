package com.sap.pq_sig_benchmark.sign;

import com.sap.pq_sig_benchmark.Parameters;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTPrivateKey;
import org.example.bcpqc.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.openjdk.jmh.annotations.Param;

import java.security.KeyPair;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Function;

public class XMSSMTSignatureBenchmark extends SignatureBenchmark {
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

	public XMSSMTSignatureBenchmark() {
		super("XMSSMT", PROVIDER);
	}
	
	public XMSSMTSignatureBenchmark(String xmssmt_parameter) {
		super("XMSSMT", PROVIDER);
		this.xmssmt_parameter = xmssmt_parameter;
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

	@Override
	protected Function<KeyPair, KeyPair> getNewKeyLambda() {
		return keyPair -> {
			// Extract key shard. Enforces full generation of first tree on each layer.
			XMSSMTPrivateKey priv = (XMSSMTPrivateKey) keyPair.getPrivate();
			XMSSMTPrivateKey shard = priv.extractKeyShard(1);
			System.out.println("Extracted shard");
			return keyPair;
		};
	}
}
