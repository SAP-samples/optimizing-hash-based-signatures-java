package com.sap.pq_sig_benchmark.keygen;

import org.example.bcpqc.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.openjdk.jmh.annotations.Param;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public class SPHINCSPlusKeyGenerationBenchmark extends KeyGenerationBenchmark {
    @Param({"sha2_128f", "sha2_128s", "sha2_192f", "sha2_192s", "sha2_256f", "sha2_256s", "sha2_128f_simple", "sha2_128s_simple", "sha2_192f_simple", "sha2_192s_simple", "sha2_256f_simple", "sha2_256s_simple",
            "shake_128f", "shake_128s", "shake_192f", "shake_192s", "shake_256f", "shake_256s", "shake_128f_simple", "shake_128s_simple", "shake_192f_simple", "shake_192s_simple", "shake_256f_simple", "shake_256s_simple",
    })
    public String sphincsplus_parameter;

    public SPHINCSPlusKeyGenerationBenchmark() {
        super(PROVIDER);
    }

    @Override
    public void setUp() throws Exception {
        this.kpg = KeyPairGenerator.getInstance("SPHINCS+", provider);
        SPHINCSPlusParameterSpec parameterSpec = (SPHINCSPlusParameterSpec) SPHINCSPlusParameterSpec.class.getField(this.sphincsplus_parameter).get(null);
        this.kpg.initialize(parameterSpec, new SecureRandom());
    }
}
