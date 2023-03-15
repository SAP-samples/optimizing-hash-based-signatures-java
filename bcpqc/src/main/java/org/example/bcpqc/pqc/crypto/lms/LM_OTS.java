package org.example.bcpqc.pqc.crypto.lms;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.lms.LMSException;
import org.bouncycastle.util.Arrays;
import org.example.bcpqc.experiments.hashing.HashingProvider;
import org.example.bcpqc.experiments.hashing.HashingProviderProvider;
import org.example.bcpqc.pqc.crypto.lms.hash.LMSHash;

class LM_OTS {

    private static final short D_PBLC = (short) 0x8080;
    private static final int ITER_K = 20;
    private static final int ITER_PREV = 23;
    private static final int ITER_J = 22;
    static final int SEED_RANDOMISER_INDEX = ~2;

    static final short D_MESG = (short) 0x8181;


    public static int coef(byte[] S, int i, int w) {
        int index = (i * w) / 8;
        int digits_per_byte = 8 / w;
        int shift = w * (~i & (digits_per_byte - 1));
        int mask = (1 << w) - 1;

        return (S[index] >>> shift) & mask;
    }


    public static int cksm(byte[] S, int sLen, LMOtsParameters parameters) {
        int sum = 0;

        int w = parameters.getW();

        // NB assumption about size of "w" not overflowing integer.
        int twoWpow = (1 << w) - 1;

        for (int i = 0; i < (sLen * 8 / parameters.getW()); i++) {
            sum = sum + twoWpow - coef(S, i, parameters.getW());
        }
        return sum << parameters.getLs();
    }


    public static LMOtsPublicKey lms_ots_generatePublicKey(LMOtsPrivateKey privateKey) {
        byte[] K = lms_ots_generatePublicKey(privateKey.getParameter(), privateKey.getI(), privateKey.getQ(), privateKey.getMasterSecret());
        return new LMOtsPublicKey(privateKey.getParameter(), privateKey.getI(), privateKey.getQ(), K);
    }

    static byte[] lms_ots_generatePublicKey(LMOtsParameters parameter, byte[] I, int q, byte[] masterSecret) {
        //
        // Start hash that computes the final value.
        //
        Digest publicContext = HashingProviderProvider.getHashingProvider().getDigest(parameter.getDigestOID());
        int digestSize = parameter.getN();
        byte[] prehashPrefix = Composer.compose()
                .bytes(I)
                .u32str(q)
                .u16str(D_PBLC)
                .padUntil(0, 22)
                .build();
        publicContext.update(prehashPrefix, 0, prehashPrefix.length);

        SeedDerive derive = new SeedDerive(I, masterSecret, parameter.getDigestOID(), parameter.getN());
        derive.setQ(q);
        derive.setJ(0);

        int p = parameter.getP();
        int n = parameter.getN();
        final int twoToWminus1 = (1 << parameter.getW()) - 1;

        byte[] buf = new byte[n];
        LMSHash lmsHash = HashingProviderProvider.getHashingProvider().newLMSHash(parameter.getDigestOID(), n);

        for (int i = 0; i < p; i++) {
            derive.deriveSeed(buf, i < p - 1, 0); // Private Key!

            for (int j = 0; j < twoToWminus1; j++) {
                lmsHash.otsChain(I, q, i, j, buf, buf);
            }
            publicContext.update(buf, 0, n);
        }

        byte[] K = new byte[digestSize];
        DigestUtil.doFinal(publicContext, K, 0, digestSize);

        return K;

    }

    public static LMOtsSignature lm_ots_generate_signature(LMSigParameters sigParams, LMOtsPrivateKey privateKey, byte[][] path, byte[] message, boolean preHashed) {
        //
        // Add the randomizer.
        //

        byte[] C;
        byte[] Q = new byte[privateKey.getParameter().getN() + 2];

        if (!preHashed) {
            LMSContext qCtx = privateKey.getSignatureContext(sigParams, path);

            LmsUtils.byteArray(message, 0, message.length, qCtx);

            C = qCtx.getC();
            Q = qCtx.getQ();
        } else {
            C = new byte[privateKey.getParameter().getN()];
            System.arraycopy(message, 0, Q, 0, privateKey.getParameter().getN());
        }

        return lm_ots_generate_signature(privateKey, Q, C);
    }

    public static LMOtsSignature lm_ots_generate_signature(LMOtsPrivateKey privateKey, byte[] Q, byte[] C) {
        LMOtsParameters parameter = privateKey.getParameter();

        int n = parameter.getN();
        int p = parameter.getP();
        int w = parameter.getW();
        byte[] pk_I = privateKey.getI();
        int pk_q = privateKey.getQ();

        ASN1ObjectIdentifier digestOID = parameter.getDigestOID();

        byte[] sigComposer = new byte[p * n];

        SeedDerive derive = privateKey.getDerivationFunction();

        int cs = cksm(Q, n, parameter);
        Q[n] = (byte) ((cs >>> 8) & 0xFF);
        Q[n + 1] = (byte) cs;

        byte[] tmp = new byte[n];
        LMSHash lmsHash = HashingProviderProvider.getHashingProvider().newLMSHash(parameter.getDigestOID(), n);

        derive.setJ(0);
        for (int i = 0; i < p; i++) {
            derive.deriveSeed(tmp, i < p - 1, 0);
            int a = coef(Q, i, w);
            for (int j = 0; j < a; j++) {
                lmsHash.otsChain(pk_I, pk_q, i, j, tmp, tmp);
            }
            System.arraycopy(tmp, 0, sigComposer, n * i, n);
        }

        return new LMOtsSignature(parameter, C, sigComposer);
    }

    public static boolean lm_ots_validate_signature(LMOtsPublicKey publicKey, LMOtsSignature signature, byte[] message, boolean prehashed)
            throws LMSException {
        if (!signature.getType().equals(publicKey.getParameter())) {
            throw new LMSException("public key and signature ots types do not match");
        }
        return Arrays.areEqual(lm_ots_validate_signature_calculate(publicKey, signature, message), publicKey.getK());
    }

    public static byte[] lm_ots_validate_signature_calculate(LMOtsPublicKey publicKey, LMOtsSignature signature, byte[] message) {
        LMSContext ctx = publicKey.createOtsContext(signature);

        LmsUtils.byteArray(message, ctx);

        return lm_ots_validate_signature_calculate(ctx);
    }

    public static byte[] lm_ots_validate_signature_calculate(LMSContext context) {
        LMOtsPublicKey publicKey = context.getPublicKey();
        LMOtsParameters parameter = publicKey.getParameter();
        Object sig = context.getSignature();
        LMOtsSignature signature;
        if (sig instanceof LMSSignature) {
            signature = ((LMSSignature) sig).getOtsSignature();
        } else {
            signature = (LMOtsSignature) sig;
        }

        int n = parameter.getN();
        int w = parameter.getW();
        int p = parameter.getP();
        byte[] Q = context.getQ();

        int cs = cksm(Q, n, parameter);
        Q[n] = (byte) ((cs >>> 8) & 0xFF);
        Q[n + 1] = (byte) cs;

        byte[] I = publicKey.getI();
        int q = publicKey.getQ();

        ASN1ObjectIdentifier digestOID = parameter.getDigestOID();
        Digest finalContext = HashingProviderProvider.getHashingProvider().getDigest(digestOID);
        LmsUtils.byteArray(I, finalContext);
        LmsUtils.u32str(q, finalContext);
        LmsUtils.u16str(D_PBLC, finalContext);

        int max_digit = (1 << w) - 1;

        byte[] y = signature.getY();
        byte[] tmp = new byte[n];
        LMSHash lmsHash = HashingProviderProvider.getHashingProvider().newLMSHash(parameter.getDigestOID(), n);

        for (int i = 0; i < p; i++) {
            System.arraycopy(y, i * n, tmp, 0, n);
            int a = coef(Q, i, w);

            for (int j = a; j < max_digit; j++) {
                lmsHash.otsChain(I, q, i, j, tmp, tmp);
            }

            finalContext.update(tmp, 0, n);
        }

        byte[] K = new byte[n];
        DigestUtil.doFinal(finalContext, K, 0, n);

        return K;
    }
}
