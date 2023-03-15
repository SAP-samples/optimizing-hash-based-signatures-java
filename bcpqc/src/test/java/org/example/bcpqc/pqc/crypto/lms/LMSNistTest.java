package org.example.bcpqc.pqc.crypto.lms;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.security.SecureRandom;

public class LMSNistTest extends TestCase {

    static final byte[] MSG = "Some message".getBytes();

    public void testSHAKE256_256() {
        testKeyGenSigVer(LMSigParameters.lms_shake_m32_h5, LMOtsParameters.shake_n32_w4);
    }

    public void testSHAKE256_192() {
        testKeyGenSigVer(LMSigParameters.lms_shake_m24_h10, LMOtsParameters.shake_n24_w8);
    }

    public void testSHA256_192() {
        testKeyGenSigVer(LMSigParameters.lms_sha256_m24_h5, LMOtsParameters.sha256_n24_w2);
    }


    public void testKeyGenSigVer(LMSigParameters sigParameters, LMOtsParameters otsParameters) {
        LMSKeyGenerationParameters keyGenerationParameters = new LMSKeyGenerationParameters(new LMSParameters(sigParameters, otsParameters), new SecureRandom());
        // Generate the private key.
        LMSKeyPairGenerator keyPairGenerator = new LMSKeyPairGenerator();
        keyPairGenerator.init(keyGenerationParameters);
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();


        LMSPrivateKeyParameters lmsPrivateKey = (LMSPrivateKeyParameters) keyPair.getPrivate();
        LMSPublicKeyParameters publicKey = lmsPrivateKey.getPublicKey();

        lmsPrivateKey.extractKeyShard(3);

        LMSSignature signature = LMS.generateSign(lmsPrivateKey, MSG);

        assertTrue(LMS.verifySignature(publicKey, signature, MSG));

    }


}
