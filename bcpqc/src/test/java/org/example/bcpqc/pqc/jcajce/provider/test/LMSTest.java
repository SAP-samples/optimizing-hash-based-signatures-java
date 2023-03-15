package org.example.bcpqc.pqc.jcajce.provider.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.example.bcpqc.pqc.crypto.lms.LMOtsParameters;
import org.example.bcpqc.pqc.crypto.lms.LMSigParameters;
import org.example.bcpqc.pqc.jcajce.provider.SAPBouncyCastlePQCProvider;
import org.example.bcpqc.pqc.jcajce.spec.LMSHSSKeyGenParameterSpec;
import org.example.bcpqc.pqc.jcajce.spec.LMSKeyGenParameterSpec;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * LMS is now promoted to the BC provider.
 */
public class LMSTest
        extends TestCase {
    public void setUp() {
        if (Security.getProvider(SAPBouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new SAPBouncyCastlePQCProvider());
        }
    }

    public void testKeyPairGenerators()
            throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", SAPBouncyCastlePQCProvider.PROVIDER_NAME);
        KeyPair kp = kpGen.generateKeyPair();
        trySigning(kp);

        kpGen.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_m32_h5, LMOtsParameters.sha256_n32_w1));
        kp = kpGen.generateKeyPair();
        trySigning(kp);

        kpGen.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_m24_h5, LMOtsParameters.sha256_n24_w1));
        kp = kpGen.generateKeyPair();
        trySigning(kp);

        kpGen.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_shake_m32_h5, LMOtsParameters.shake_n32_w1));
        kp = kpGen.generateKeyPair();
        trySigning(kp);

        kpGen.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_shake_m24_h5, LMOtsParameters.shake_n24_w1));
        kp = kpGen.generateKeyPair();
        trySigning(kp);

        kpGen.initialize(new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_m32_h5, LMOtsParameters.sha256_n32_w1),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_m32_h5, LMOtsParameters.sha256_n32_w1)
        ), new SecureRandom());
        kp = kpGen.generateKeyPair();
        trySigning(kp);
    }

    private void trySigning(KeyPair keyPair)
            throws Exception {
        byte[] msg = Strings.toByteArray("Hello, world!");
        Signature signer = Signature.getInstance("LMS", SAPBouncyCastlePQCProvider.PROVIDER_NAME);

        signer.initSign(keyPair.getPrivate(), new SecureRandom());

        signer.update(msg);

        byte[] sig = signer.sign();

        signer.initVerify(keyPair.getPublic());

        signer.update(msg);

        assertTrue(signer.verify(sig));
    }

    public void testKeyFactoryLMSKey()
            throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", SAPBouncyCastlePQCProvider.PROVIDER_NAME);

        kpGen.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_m32_h5, LMOtsParameters.sha256_n32_w1));

        KeyPair kp = kpGen.generateKeyPair();

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());

        KeyFactory kFact = KeyFactory.getInstance("LMS", SAPBouncyCastlePQCProvider.PROVIDER_NAME);

        PublicKey pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

        PrivateKey priv1 = kFact.generatePrivate(pkcs8KeySpec);

        assertEquals(kp.getPrivate(), priv1);

        kFact = KeyFactory.getInstance(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig.getId(), SAPBouncyCastlePQCProvider.PROVIDER_NAME);

        pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);
    }

    public void testPublicKeyEncodingLength()
            throws Exception {
        KeyPairGenerator kpGen1 = KeyPairGenerator.getInstance("LMS", SAPBouncyCastlePQCProvider.PROVIDER_NAME);

        kpGen1.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_m32_h5, LMOtsParameters.sha256_n32_w1));

        KeyPair kp1 = kpGen1.generateKeyPair();

        KeyPairGenerator kpGen2 = KeyPairGenerator.getInstance("LMS", SAPBouncyCastlePQCProvider.PROVIDER_NAME);

        kpGen2.initialize(new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_m32_h5, LMOtsParameters.sha256_n32_w1),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_m32_h5, LMOtsParameters.sha256_n32_w1)
        ), new SecureRandom());

        KeyPair kp2 = kpGen2.generateKeyPair();

        assertEquals(kp1.getPublic().getEncoded().length, kp2.getPublic().getEncoded().length);
    }

    public void testKeyFactoryHSSKey()
            throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", SAPBouncyCastlePQCProvider.PROVIDER_NAME);

        kpGen.initialize(new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_m32_h5, LMOtsParameters.sha256_n32_w1),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_m32_h5, LMOtsParameters.sha256_n32_w1)
        ), new SecureRandom());

        KeyPair kp = kpGen.generateKeyPair();

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());

        KeyFactory kFact = KeyFactory.getInstance("LMS", SAPBouncyCastlePQCProvider.PROVIDER_NAME);

        PublicKey pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

        PrivateKey priv1 = kFact.generatePrivate(pkcs8KeySpec);

        assertEquals(kp.getPrivate(), priv1);

        kFact = KeyFactory.getInstance(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig.getId(), SAPBouncyCastlePQCProvider.PROVIDER_NAME);

        pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);
    }

    public void testKeyGenAndSignTwoSigsWithShardHSS()
            throws Exception {
        byte[] msg1 = Strings.toByteArray("Hello, world!");
        byte[] msg2 = Strings.toByteArray("Now is the time");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", SAPBouncyCastlePQCProvider.PROVIDER_NAME);

        kpGen.initialize(
                new LMSHSSKeyGenParameterSpec(
                        new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_m32_h5, LMOtsParameters.sha256_n32_w4),
                        new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_m32_h5, LMOtsParameters.sha256_n32_w4)), new SecureRandom());

        KeyPair kp = kpGen.generateKeyPair();

        LMSPrivateKey privKey = ((LMSPrivateKey) kp.getPrivate()).extractKeyShard(2);

        assertEquals(2, ((LMSPrivateKey) kp.getPrivate()).getIndex());

        assertEquals(2, privKey.getUsagesRemaining());
        assertEquals(0, privKey.getIndex());

        Signature signer = Signature.getInstance("LMS", SAPBouncyCastlePQCProvider.PROVIDER_NAME);

        signer.initSign(privKey);

        signer.update(msg1);

        byte[] sig1 = signer.sign();

        assertEquals(1, privKey.getIndex());

        signer.initVerify(kp.getPublic());

        signer.update(msg1);

        assertTrue(signer.verify(sig1));

        signer.initSign(privKey);

        signer.update(msg2);

        byte[] sig2 = signer.sign();

        assertEquals(0, privKey.getUsagesRemaining());

        try {
            signer.update(msg2);

            fail("no exception");
        } catch (SignatureException e) {
            assertEquals("hss private key shard is exhausted", e.getMessage());
        }

        signer = Signature.getInstance("LMS", SAPBouncyCastlePQCProvider.PROVIDER_NAME);

        signer.initVerify(kp.getPublic());

        signer.update(msg2);

        assertTrue(signer.verify(sig2));

        try {
            signer.initSign(privKey);
            fail("no exception");
        } catch (InvalidKeyException e) {
            assertEquals("private key exhausted", e.getMessage());
        }

        assertEquals(2, ((LMSPrivateKey) kp.getPrivate()).getIndex());

        signer.initSign(kp.getPrivate());

        signer.update(msg1);

        byte[] sig = signer.sign();

        signer.initVerify(kp.getPublic());

        signer.update(msg1);

        assertTrue(signer.verify(sig));
        assertFalse(Arrays.areEqual(sig1, sig));
        assertEquals(3, ((LMSPrivateKey) kp.getPrivate()).getIndex());
    }
}
