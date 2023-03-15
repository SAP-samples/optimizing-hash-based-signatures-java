package org.example.bcpqc.pqc.crypto.sphincsplus;

import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

public class SPHINCSPlusKeyGenerationParameters
        extends KeyGenerationParameters {
    private final SPHINCSPlusParameters parameters;

    public SPHINCSPlusKeyGenerationParameters(SecureRandom random, SPHINCSPlusParameters parameters) {
        super(random, -1);
        this.parameters = parameters;
    }

    SPHINCSPlusParameters getParameters() {
        return parameters;
    }
}
