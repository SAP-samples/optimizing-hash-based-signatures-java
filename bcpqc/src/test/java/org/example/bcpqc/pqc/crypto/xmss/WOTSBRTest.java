package org.example.bcpqc.pqc.crypto.xmss;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.example.bcpqc.experiments.hashing.HashingProviderProvider;

import static org.example.bcpqc.pqc.crypto.xmss.WOTSPlusCTest.assertMatrixEquals;

public class WOTSBRTest extends TestCase {
    private static void testWOTSBR(String hashingProvider, boolean useOnePadding, int iterationsR, boolean includeChecksum, int expectedCtr, int winternitzParameter) {
        HashingProviderProvider.setHashingProvider(hashingProvider);
        WOTSBRParameters wotsbrParameters = new WOTSBRParameters(NISTObjectIdentifiers.id_sha256, 32, useOnePadding, iterationsR, includeChecksum, winternitzParameter);
        WOTSBR wotsbr = new WOTSBR(wotsbrParameters);

        byte[] privSeed = new byte[32];
        privSeed[0] = 12;
        byte[] pubSeed = new byte[32];
        pubSeed[0] = 34;
        byte[] msg = new byte[32];
        msg[0] = 56;
        byte[] key = new byte[96];
        key[0] = 78;

        wotsbr.importKeys(privSeed, pubSeed);

        OTSHashAddress otsAddress = (OTSHashAddress) new OTSHashAddress.Builder().build();
        byte[][] pubKey = wotsbr.getPublicKey(otsAddress).toByteArray();

        // Sign
        WOTSBRSignature wotsPlusCtrSignature = wotsbr.signMessage(key, msg, otsAddress);

        assertNotNull(wotsPlusCtrSignature);
        System.out.println("Counter: " + wotsPlusCtrSignature.getCtr());
        assertEquals(expectedCtr, wotsPlusCtrSignature.getCtr());

        // Extract pubkey from signature (= verify)
        wotsbr = new WOTSBR(wotsbrParameters);
        wotsbr.importKeys(new byte[wotsbrParameters.getTreeDigestSize()], pubSeed);

        byte[][] pubKeyFromSignature = wotsbr.getPublicKeyFromSignatureAndMessage(key, msg, wotsPlusCtrSignature, otsAddress).toByteArray();

        assertMatrixEquals(pubKey, pubKeyFromSignature);
    }

    public void testFewIterationsJavaOptimized() {
        testWOTSBR("java-optimized", false, 100, false, 43, 16);
    }

    public void testManyIterationsJavaOptimized() {
        testWOTSBR("java-optimized", false, 10000000, false, 2654505, 16);
    }

    public void testFewIterationsBCOptimized() {
        testWOTSBR("bc-optimized", false, 100, false, 43, 16);
    }

    public void testManyIterationsBCOptimized() {
        testWOTSBR("bc-optimized", false, 10000000, false, 2654505, 16);
    }

    public void testFewIterationsBCOptimizedOnePadding() {
        testWOTSBR("bc-optimized", true, 100, false, 43, 16);
    }

    public void testWinternitz4() {
        testWOTSBR("java-optimized", false, 100, false, 15, 4);
    }


}
