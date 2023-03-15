package org.example.bcpqc.pqc.crypto.xmss;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.example.bcpqc.experiments.hashing.HashingProviderProvider;

public class WOTSPlusCTest extends TestCase {

    private static void testWOTSPlusC(String hashingProvider, int n, int logW, int s, int z, long expectedCtr) {
        HashingProviderProvider.setHashingProvider(hashingProvider);

        byte[] privSeed = new byte[32];
        privSeed[0] = 12;
        byte[] pubSeed = new byte[32];
        pubSeed[0] = 34;
        byte[] msg = new byte[32];
        msg[0] = 56;
        byte[] key = new byte[96];
        key[0] = 78;


        WOTSPlusCParameters param = new WOTSPlusCParameters(NISTObjectIdentifiers.id_sha256, 32, s, 0, 16);
        WOTSPlusC wotsPlusC = new WOTSPlusC(param);
        wotsPlusC.importKeys(privSeed, pubSeed);

        OTSHashAddress otsAddress = (OTSHashAddress) new OTSHashAddress.Builder().build();
        byte[][] pubKey = wotsPlusC.getPublicKey(otsAddress).toByteArray();

        // Sign
        WOTSPlusCtrSignature wotsPlusCtrSignature = wotsPlusC.signMessage(key, msg, otsAddress);

        assertNotNull(wotsPlusCtrSignature);
        System.out.println("Counter: " + wotsPlusCtrSignature.getCtr());
        assertEquals(expectedCtr, wotsPlusCtrSignature.getCtr());

        // Extract pubkey from signature (= verify)
        wotsPlusC = new WOTSPlusC(param);
        wotsPlusC.importKeys(new byte[param.getTreeDigestSize()], pubSeed);

        byte[][] pubKeyFromSignature = wotsPlusC.getPublicKeyFromSignatureAndMessage(key, msg, wotsPlusCtrSignature, otsAddress).toByteArray();

        assertMatrixEquals(pubKey, pubKeyFromSignature);

    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        HashingProviderProvider.setHashingProvider("java-optimized");
    }

    static void assertMatrixEquals(byte[][] a, byte[][] b) {
        assertEquals(a.length, b.length);
        for (int i = 0; i < a.length; i++) {
            assertEquals(a[i].length, b[i].length);
            for (int j = 0; j < a[i].length; j++) {
                assertEquals("Difference at (" + i + ", " + j + ")", a[i][j], b[i][j]);
            }
        }
    }

    public static void main(String[] args) {
        int n = 256;
        int logW = 4;
        int s = 680;

        testWOTSPlusC("java-optimized", n, logW, s, 0, 1);

    }

    public void testSign1JavaOptimized() {
        int n = 256;
        int logW = 4;
        // WIll be correct on first iteration
        int s = 467;
        System.out.println("Using s = " + s);

        testWOTSPlusC("java-optimized", n, logW, s, 0, 0);
    }

    public void testSign2JavaOptimized() {
        int n = 256;
        int logW = 4;
        int s = 660;
        System.out.println("Using s = " + s);

        testWOTSPlusC("java-optimized", n, logW, s, 0, 8663072);
    }

    public void testSignWithZJavaOptimized() {
        int n = 256;
        int logW = 4;
        int s = (n / logW) * ((1 << logW) - 1) / 2;
        int z = 2;
        System.out.println("Using s = " + s + ", z = " + z);

        testWOTSPlusC("java-optimized", n, logW, s, 2, 78);
    }

    public void testSignBCOoptimized() {
        int n = 256;
        int logW = 4;
        int s = (n / logW) * ((1 << logW) - 1) / 2;
        int z = 2;
        System.out.println("Using s = " + s + ", z = " + z);

        testWOTSPlusC("bc-optimized", n, logW, s, 2, 78);
    }
}
