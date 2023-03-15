package com.sap.pq_sig_benchmark.verify;

import org.example.bcpqc.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.openjdk.jmh.annotations.Param;

import java.security.spec.AlgorithmParameterSpec;

public class SPHINCSPlusVerificationBenchmark extends VerificationBenchmark {
    @Param({"sha2_128f", "sha2_128s", "sha2_192f", "sha2_192s", "sha2_256f", "sha2_256s", "sha2_128f_simple", "sha2_128s_simple", "sha2_192f_simple", "sha2_192s_simple", "sha2_256f_simple", "sha2_256s_simple",
            "shake_128f", "shake_128s", "shake_192f", "shake_192s", "shake_256f", "shake_256s", "shake_128f_simple", "shake_128s_simple", "shake_192f_simple", "shake_192s_simple", "shake_256f_simple", "shake_256s_simple",
    })
    public String sphincsplus_parameter;


    public SPHINCSPlusVerificationBenchmark() {
        super("SPHINCSPLUS", PROVIDER);
    }
    
    @Override
    protected AlgorithmParameterSpec getParameterSpec() throws Exception {
        return (SPHINCSPlusParameterSpec) SPHINCSPlusParameterSpec.class.getField(this.sphincsplus_parameter).get(null);
    }

    @Override
    protected String getSignatureAlgorithm() {
        return "SPHINCSPLUS";
    }

    @Override
    protected String getParameter() {
        return this.sphincsplus_parameter;
    }
}
