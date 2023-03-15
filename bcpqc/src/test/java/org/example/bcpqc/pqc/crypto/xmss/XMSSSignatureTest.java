package org.example.bcpqc.pqc.crypto.xmss;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.Arrays;

/**
 * Test cases for XMSSSignature class.
 */
public class XMSSSignatureTest
        extends TestCase {

    private void signatureParsingTest(XMSSParameters params) {
        XMSS xmss = new XMSS(params, new NullPRNG());
        xmss.generateKeys();
        byte[] message = new byte[1024];
        byte[] sig1 = xmss.sign(message);
        XMSSSignature sig2 = new XMSSSignature.Builder(params).withSignature(sig1).build();

        byte[] sig3 = sig2.toByteArray();
        assertEquals(true, Arrays.areEqual(sig1, sig3));

    }

    public void testSignatureParsingSHA256() {
        signatureParsingTest(new XMSSParameters(10, NISTObjectIdentifiers.id_sha256, 32));
    }

    public void testSignatureParsingSHA512() {
        signatureParsingTest(new XMSSParameters(10, NISTObjectIdentifiers.id_sha512, 64));
    }

    public void testSignatureParsingSHA256_192() {
        signatureParsingTest(new XMSSParameters(10, NISTObjectIdentifiers.id_sha256, 24));
    }


    public void testConstructor() {
        XMSSParameters params = new XMSSParameters(10, new SHA256Digest());
        XMSSSignature sig = new XMSSSignature.Builder(params).build();

        byte[] sigByte = sig.toByteArray();
        /* check everything is 0 */
        for (int i = 0; i < sigByte.length; i++) {
            assertEquals(0x00, sigByte[i]);
        }
    }
}
