package org.example.bcpqc.pqc.crypto.xmss;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.util.Arrays;

import java.io.IOException;

/**
 * Test cases for XMSSPrivateKey class.
 */
public class XMSSPrivateKeyTest
        extends TestCase {
    public void testPrivateKeyParsing()
            throws ClassNotFoundException, IOException {
        parsingTest(new XMSSParameters(10, NISTObjectIdentifiers.id_sha256, 32));
        parsingTest(new XMSSParameters(10, NISTObjectIdentifiers.id_sha512, 64));
        parsingTest(new XMSSParameters(10, NISTObjectIdentifiers.id_shake128, 32));
        parsingTest(new XMSSParameters(10, NISTObjectIdentifiers.id_shake256, 64));

        parsingTest(new XMSSParameters(10, NISTObjectIdentifiers.id_sha256, 24));
        parsingTest(new XMSSParameters(10, NISTObjectIdentifiers.id_shake256, 32));
        parsingTest(new XMSSParameters(10, NISTObjectIdentifiers.id_shake256, 24));

    }

    private void parsingTest(XMSSParameters params)
            throws ClassNotFoundException, IOException {
        byte[] root = generateRoot(params.getTreeDigestSize());
        XMSSPrivateKeyParameters privateKey = new XMSSPrivateKeyParameters.Builder(params).withRoot(root).build();

        byte[] export = privateKey.toByteArray();

        XMSSPrivateKeyParameters privateKey2 = new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(export).build();

        assertEquals(privateKey.getIndex(), privateKey2.getIndex());
        assertEquals(true, Arrays.areEqual(privateKey.getSecretKeySeed(), privateKey2.getSecretKeySeed()));
        assertEquals(true, Arrays.areEqual(privateKey.getSecretKeyPRF(), privateKey2.getSecretKeyPRF()));
        assertEquals(true, Arrays.areEqual(privateKey.getPublicSeed(), privateKey2.getPublicSeed()));
        assertEquals(true, Arrays.areEqual(privateKey.getRoot(), privateKey2.getRoot()));
    }

    private byte[] generateRoot(int digestSize) {
        byte[] rv = new byte[digestSize];

        for (int i = 0; i != rv.length; i++) {
            rv[i] = (byte) i;
        }

        return rv;
    }

}
