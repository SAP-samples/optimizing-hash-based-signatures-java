package com.sap.pq_sig_benchmark.sign;

import com.sap.pq_sig_benchmark.Parameters;
import com.sap.pq_sig_benchmark.util.LMSHelper;
import org.openjdk.jmh.annotations.Param;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;

public class LMSSignatureBenchmark extends SignatureBenchmark {

    @Param({Parameters.LMS_SIG_SHA256_M32_H5, Parameters.LMS_SIG_SHA256_M32_H10, Parameters.LMS_SIG_SHA256_M32_H15,
            Parameters.LMS_SIG_SHA256_M32_H20, Parameters.LMS_SIG_SHA256_M32_H25,
            Parameters.LMS_SIG_SHA256_M24_H5, Parameters.LMS_SIG_SHA256_M24_H10, Parameters.LMS_SIG_SHA256_M24_H15,
            //Parameters.LMS_SIG_SHA256_M24_H20, Parameters.LMS_SIG_SHA256_M24_H25,
            Parameters.LMS_SIG_SHAKE_M32_H5, Parameters.LMS_SIG_SHAKE_M32_H10, Parameters.LMS_SIG_SHAKE_M32_H15,
            //Parameters.LMS_SIG_SHAKE_M32_H20, Parameters.LMS_SIG_SHAKE_M32_H25,
            Parameters.LMS_SIG_SHAKE_M24_H5, Parameters.LMS_SIG_SHAKE_M24_H10, Parameters.LMS_SIG_SHAKE_M24_H15,
            //Parameters.LMS_SIG_SHAKE_M24_H20, Parameters.LMS_SIG_SHAKE_M24_H25
    })
    String lms_sig_parameter;

    public LMSSignatureBenchmark() {
        super("LMS", PROVIDER);
    }

    @Override
    protected AlgorithmParameterSpec getParameterSpec() throws Exception {
        return LMSHelper.buildKeyGenParameterSpec(lms_sig_parameter);

    }

    @Override
    protected String getSignatureAlgorithm() {
        return "LMS";
    }

    @Override
    protected String getParameter() {
        return this.lms_sig_parameter;
    }

    // For LMS, we need to generate a new key every time because the private key's node cache is not serialized.
    // Therefore, its entries must be re-generated when a key is deserialized, causing the signature time to be
    // significantly longer.
    @Override
    public void setUp() throws Exception {
        System.out.print("generating key... ");
        KeyFactory keyFactory = KeyFactory.getInstance("LMS", provider);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("LMS", provider);
        AlgorithmParameterSpec parameterSpec = getParameterSpec();

        kpg.initialize(parameterSpec, new SecureRandom());
        this.kp = kpg.generateKeyPair();

        this.sig = Signature.getInstance(this.getSignatureAlgorithm(), provider);
        this.sig.initSign(this.kp.getPrivate());

        System.out.println("Setup done.");
    }
}
