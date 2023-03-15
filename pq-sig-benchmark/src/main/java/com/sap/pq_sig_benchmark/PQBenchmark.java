package com.sap.pq_sig_benchmark;

import org.example.bcpqc.experiments.hashing.HashingProviderProvider;

import java.security.Security;

public abstract class PQBenchmark {
    // The forked Bouncy Castle provider. As of now, it only works with XMSS and XMSSMT.
    protected static final String PROVIDER = org.example.bcpqc.pqc.jcajce.provider.SAPBouncyCastlePQCProvider.PROVIDER_NAME;

    // For LMS, we need the unmodified BC provider.
    protected static final String BC_PROVIDER = org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider.PROVIDER_NAME;

    protected final String provider;

    public PQBenchmark(String provider) {
        this.provider = provider;
        if (Security.getProvider(provider) == null) {
            if (provider.equals(PROVIDER)) {
                Security.addProvider(new org.example.bcpqc.pqc.jcajce.provider.SAPBouncyCastlePQCProvider());
            } else if (provider.equals(BC_PROVIDER)) {
                Security.addProvider(new org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider());
            }
        }
    }

    protected void setHashingProvider(String hashingProvider, boolean parallel) {
        HashingProviderProvider.setHashingProvider(hashingProvider);
        HashingProviderProvider.EXECUTE_PARALLEL = parallel;
    }
}
