package com.sap.pq_sig_benchmark.keygen;

import com.sap.pq_sig_benchmark.Parameters;
import com.sap.pq_sig_benchmark.util.LMSHelper;
import org.example.bcpqc.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.openjdk.jmh.annotations.Param;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public class LMSKeyGenerationBenchmark extends KeyGenerationBenchmark {

    @Param({Parameters.LMS_SIG_SHA256_M32_H5, Parameters.LMS_SIG_SHA256_M32_H10, Parameters.LMS_SIG_SHA256_M32_H15,
            Parameters.LMS_SIG_SHA256_M32_H20, Parameters.LMS_SIG_SHA256_M32_H25,
            Parameters.LMS_SIG_SHA256_M24_H5, Parameters.LMS_SIG_SHA256_M24_H10, Parameters.LMS_SIG_SHA256_M24_H15,
            Parameters.LMS_SIG_SHA256_M24_H20, Parameters.LMS_SIG_SHA256_M24_H25,
            Parameters.LMS_SIG_SHAKE_M32_H5, Parameters.LMS_SIG_SHAKE_M32_H10, Parameters.LMS_SIG_SHAKE_M32_H15,
            Parameters.LMS_SIG_SHAKE_M32_H20, Parameters.LMS_SIG_SHAKE_M32_H25,
            Parameters.LMS_SIG_SHAKE_M24_H5, Parameters.LMS_SIG_SHAKE_M24_H10, Parameters.LMS_SIG_SHAKE_M24_H15,
            Parameters.LMS_SIG_SHAKE_M24_H20, Parameters.LMS_SIG_SHAKE_M24_H25})
    String lms_sig_parameter;

    public LMSKeyGenerationBenchmark() {
        super(PROVIDER);
    }

    @Override
    public void setUp() throws Exception {
        this.kpg = KeyPairGenerator.getInstance("LMS", provider);

        LMSKeyGenParameterSpec parameterSpec = LMSHelper.buildKeyGenParameterSpec(lms_sig_parameter);

        this.kpg.initialize(parameterSpec, new SecureRandom());
    }

}
