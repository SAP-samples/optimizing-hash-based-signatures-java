package org.example.bcpqc.pqc.crypto.lms;


import org.bouncycastle.crypto.Digest;
import org.example.bcpqc.experiments.hashing.HashingProvider;
import org.example.bcpqc.experiments.hashing.HashingProviderProvider;

import static org.example.bcpqc.pqc.crypto.lms.LM_OTS.D_MESG;
import static org.example.bcpqc.pqc.crypto.lms.LM_OTS.SEED_RANDOMISER_INDEX;


class LMOtsPrivateKey {
    private final LMOtsParameters parameter;
    private final byte[] I;
    private final int q;
    private final byte[] masterSecret;
    private final HashingProvider hashingProvider = HashingProviderProvider.getHashingProvider();

    public LMOtsPrivateKey(LMOtsParameters parameter, byte[] i, int q, byte[] masterSecret) {
        this.parameter = parameter;
        I = i;
        this.q = q;
        this.masterSecret = masterSecret;
    }

    LMSContext getSignatureContext(LMSigParameters sigParams, byte[][] path) {
        byte[] C = new byte[parameter.getN()];

        SeedDerive derive = getDerivationFunction();
        derive.setJ(SEED_RANDOMISER_INDEX); // This value from reference impl.
        derive.deriveSeed(C, false);

        Digest ctx = hashingProvider.getDigest(parameter.getDigestOID());

        LmsUtils.byteArray(this.getI(), ctx);
        LmsUtils.u32str(this.getQ(), ctx);
        LmsUtils.u16str(D_MESG, ctx);
        LmsUtils.byteArray(C, ctx);

        return new LMSContext(this, sigParams, ctx, C, path);
    }

    SeedDerive getDerivationFunction() {
        SeedDerive derive = new SeedDerive(I, masterSecret, parameter.getDigestOID(), this.parameter.getN());
        derive.setQ(q);
        return derive;
    }


    public LMOtsParameters getParameter() {
        return parameter;
    }

    public byte[] getI() {
        return I;
    }

    public int getQ() {
        return q;
    }

    public byte[] getMasterSecret() {
        return masterSecret;
    }
}
