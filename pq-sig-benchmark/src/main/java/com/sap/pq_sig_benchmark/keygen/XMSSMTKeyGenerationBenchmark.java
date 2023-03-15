package com.sap.pq_sig_benchmark.keygen;

import com.sap.pq_sig_benchmark.Parameters;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTPrivateKey;
import org.bouncycastle.util.Strings;
import org.example.bcpqc.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.infra.Blackhole;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;

public class XMSSMTKeyGenerationBenchmark extends KeyGenerationBenchmark {
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

    private static final byte[] msg = Strings.toByteArray("Lorem ipsum dolor sit amet");

    @Override
    public void setUp() throws GeneralSecurityException, IllegalArgumentException, IllegalAccessException,
            NoSuchFieldException, SecurityException {
        this.kpg = KeyPairGenerator.getInstance("XMSSMT", provider);
        XMSSMTParameterSpec paramSpec = (XMSSMTParameterSpec) XMSSMTParameterSpec.class.getField(this.xmssmt_parameter)
                .get(null);
        kpg.initialize(paramSpec, new SecureRandom());
    }

    public XMSSMTKeyGenerationBenchmark() {
        super(PROVIDER);
    }

    @Override
    public Object testMethod() throws Exception {
        super.testMethod();

        // Extract key shard. Enforces full generation of first tree on each layer.
        XMSSMTPrivateKey priv = (XMSSMTPrivateKey) this.kp.getPrivate();
        return priv.extractKeyShard(1);
    }
}
