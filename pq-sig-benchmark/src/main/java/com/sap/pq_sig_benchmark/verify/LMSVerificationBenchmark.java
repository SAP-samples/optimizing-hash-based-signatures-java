package com.sap.pq_sig_benchmark.verify;

import com.sap.pq_sig_benchmark.Parameters;
import com.sap.pq_sig_benchmark.util.LMSHelper;
import org.openjdk.jmh.annotations.Param;

import java.security.spec.AlgorithmParameterSpec;

public class LMSVerificationBenchmark extends VerificationBenchmark {
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

    public LMSVerificationBenchmark() {
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

}
