package org.example.bcpqc.pqc.crypto.lms;


import org.example.bcpqc.experiments.hashing.HashingProviderProvider;
import org.example.bcpqc.pqc.crypto.lms.hash.LMSHash;

public class LMS {
    public static final short D_LEAF = (short) 0x8282;
    public static final short D_INTR = (short) 0x8383;

    public static LMSPrivateKeyParameters generateKeys(LMSigParameters parameterSet, LMOtsParameters lmOtsParameters, int q, byte[] I, byte[] rootSeed)
            throws IllegalArgumentException {
        //
        // RFC 8554 recommends that digest used in LMS and LMOTS be of the same strength to protect against
        // attackers going after the weaker of the two digests. This is not enforced here!
        //

        // Algorithm 5, Compute LMS private key.

        // Step 1
        // -- Parameters passed in as arguments.


        // Step 2

        if (rootSeed == null || rootSeed.length < parameterSet.getM()) {
            throw new IllegalArgumentException("root seed is less than " + parameterSet.getM());
        }

        int twoToH = 1 << parameterSet.getH();

        return new LMSPrivateKeyParameters(parameterSet, lmOtsParameters, q, I, twoToH, rootSeed);
    }

    public static LMSSignature generateSign(LMSPrivateKeyParameters privateKey, byte[] message) {
        //
        // Get T from the public key.
        // This may cause the public key to be generated.
        //
        // byte[][] T = new byte[privateKey.getMaxQ()][];

        // Step 2
        LMSContext context = privateKey.generateLMSContext();

        context.update(message, 0, message.length);

        return generateSign(context);
    }

    public static LMSSignature generateSign(LMSContext context) {
        //
        // Get T from the public key.
        // This may cause the public key to be generated.
        //
        // byte[][] T = new byte[privateKey.getMaxQ()][];

        // Step 1.
        LMOtsSignature ots_signature = LM_OTS.lm_ots_generate_signature(context.getPrivateKey(), context.getQ(), context.getC());

        return new LMSSignature(context.getPrivateKey().getQ(), ots_signature, context.getSigParams(), context.getPath());
    }

//    public static boolean verifySignature(LMSPublicKeyParameters publicKey, LMSSignature S, byte[] message)
//    {
//        byte[] Tc = algorithm6a(S, publicKey.refI(), publicKey.getOtsParameters().getType(), message);
//
//        return publicKey.matchesT1(Tc);
//    }

    public static boolean verifySignature(LMSPublicKeyParameters publicKey, LMSSignature S, byte[] message) {
        LMSContext context = publicKey.generateOtsContext(S);

        LmsUtils.byteArray(message, context);

        return verifySignature(publicKey, context);
    }

    public static boolean verifySignature(LMSPublicKeyParameters publicKey, byte[] S, byte[] message) {
        LMSContext context = publicKey.generateLMSContext(S);

        LmsUtils.byteArray(message, context);

        return verifySignature(publicKey, context);
    }

    public static boolean verifySignature(LMSPublicKeyParameters publicKey, LMSContext context) {
        LMSSignature S = (LMSSignature) context.getSignature();
        LMSigParameters lmsParameter = S.getParameter();
        int h = lmsParameter.getH();
        byte[][] path = S.getY();
        byte[] Kc = LM_OTS.lm_ots_validate_signature_calculate(context);
        // Step 4
        // node_num = 2^h + q
        int node_num = (1 << h) + S.getQ();

        // tmp = H(I || u32str(node_num) || u16str(D_LEAF) || Kc)
        byte[] I = publicKey.getI();
        int digestSize = lmsParameter.getM();
        byte[] tmp = new byte[digestSize];
        LMSHash lmsHash = HashingProviderProvider.getHashingProvider().newLMSHash(lmsParameter.getDigestOID(), digestSize);

        lmsHash.treeLeaf(I, node_num, Kc, tmp);

        int i = 0;

        while (node_num > 1) {
            if ((node_num & 1) == 1) {
                // is odd
                lmsHash.treeIntermediate(I, node_num / 2, path[i], tmp, tmp);
            } else {
                lmsHash.treeIntermediate(I, node_num / 2, tmp, path[i], tmp);
            }
            node_num = node_num / 2;
            i++;
        }
        byte[] Tc = tmp;
        return publicKey.matchesT1(Tc);
    }
}
