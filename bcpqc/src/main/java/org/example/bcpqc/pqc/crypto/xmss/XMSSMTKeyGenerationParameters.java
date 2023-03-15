package org.example.bcpqc.pqc.crypto.xmss;

import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

/**
 * XMSS^MT key-pair generation parameters.
 */
public final class XMSSMTKeyGenerationParameters
        extends KeyGenerationParameters {
    private final XMSSMTParameters xmssmtParameters;

    /**
     * XMSSMT constructor...
     *
     * @param prng Secure random to use.
     */
    public XMSSMTKeyGenerationParameters(XMSSMTParameters xmssmtParameters, SecureRandom prng) {
        super(prng, -1);

        this.xmssmtParameters = xmssmtParameters;
    }

    public XMSSMTParameters getParameters() {
        return xmssmtParameters;
    }
}
