package org.example.bcpqc.pqc.jcajce.provider.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;
import org.example.bcpqc.experiments.hashing.HashingProviderProvider;
import org.example.bcpqc.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.example.bcpqc.pqc.crypto.xmss.XMSSSigner;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class XMSSSignatureSpi
        extends Signature
        implements StateAwareSignature {
    private Digest digest;
    private XMSSSigner signer;
    private SecureRandom random;
    private ASN1ObjectIdentifier treeDigest;
    private int digestSize;
    protected XMSSSignatureSpi(String algorithm) {
        super(algorithm);
    }

    protected XMSSSignatureSpi(String sigName, Digest digest, XMSSSigner signer, int digestSize) {
        super(sigName);

        this.digest = digest;
        this.signer = signer;
        this.digestSize = digestSize;
    }

    protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException {
        if (publicKey instanceof BCXMSSPublicKey) {
            CipherParameters param = ((BCXMSSPublicKey) publicKey).getKeyParams();

            treeDigest = null;
            digest.reset();
            signer.init(false, param);
        } else {
            throw new InvalidKeyException("unknown public key passed to XMSS");
        }
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException {
        this.random = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException {
        if (privateKey instanceof BCXMSSPrivateKey) {
            CipherParameters param = ((BCXMSSPrivateKey) privateKey).getKeyParams();

            treeDigest = ((BCXMSSPrivateKey) privateKey).getTreeDigestOID();
            if (random != null) {
                param = new ParametersWithRandom(param, random);
            }

            digest.reset();
            signer.init(true, param);
        } else {
            throw new InvalidKeyException("unknown private key passed to XMSS");
        }
    }

    protected void engineUpdate(byte b)
            throws SignatureException {
        digest.update(b);
    }

    protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException {
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
            throws SignatureException {
        byte[] hash = DigestUtil.getDigestResult(digest, digestSize);

        try {
            byte[] sig = signer.generateSignature(hash);

            return sig;
        } catch (Exception e) {
            if (e instanceof IllegalStateException) {
                throw new SignatureException(e.getMessage(), e);
            }
            throw new SignatureException(e.toString(), e);
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
            throws SignatureException {
        byte[] hash = DigestUtil.getDigestResult(digest, digestSize);

        return signer.verifySignature(hash, sigBytes);
    }

    protected void engineSetParameter(AlgorithmParameterSpec params) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec)
     */
    protected void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(String param) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    public boolean isSigningCapable() {
        return treeDigest != null && signer.getUsagesRemaining() != 0;
    }

    public PrivateKey getUpdatedPrivateKey() {
        if (treeDigest == null) {
            throw new IllegalStateException("signature object not in a signing state");
        }
        PrivateKey rKey = new BCXMSSPrivateKey(treeDigest, (XMSSPrivateKeyParameters) signer.getUpdatedPrivateKey());

        treeDigest = null;

        return rKey;
    }

    static public class generic
            extends XMSSSignatureSpi {
        public generic() {
            super("XMSS", new NullDigest(), new XMSSSigner(), -1);
        }
    }

    static public class withSha256
            extends XMSSSignatureSpi {
        public withSha256() {
            super("XMSS-SHA256", new NullDigest(), new XMSSSigner(), -1);
        }
    }

    static public class withShake128
            extends XMSSSignatureSpi {
        public withShake128() {
            super("XMSS-SHAKE128", new NullDigest(), new XMSSSigner(), -1);
        }
    }

    static public class withSha512
            extends XMSSSignatureSpi {
        public withSha512() {
            super("XMSS-SHA512", new NullDigest(), new XMSSSigner(), -1);
        }
    }

    static public class withShake256
            extends XMSSSignatureSpi {
        public withShake256() {
            super("XMSS-SHAKE256", new NullDigest(), new XMSSSigner(), -1);
        }
    }

    static public class withSha2_192
            extends XMSSSignatureSpi {
        public withSha2_192() {
            super("XMSS-SHA2_192", new NullDigest(), new XMSSSigner(), -1);
        }
    }

    static public class withShake256_256
            extends XMSSSignatureSpi {
        public withShake256_256() {
            super("XMSS-SHAKE256_256", new NullDigest(), new XMSSSigner(), -1);
        }
    }

    static public class withShake256_192
            extends XMSSSignatureSpi {
        public withShake256_192() {
            super("XMSS-SHAKE256_192", new NullDigest(), new XMSSSigner(), -1);
        }
    }


    static public class withSha256andPrehash
            extends XMSSSignatureSpi {
        public withSha256andPrehash() {
            super("SHA256withXMSS-SHA256", HashingProviderProvider.getHashingProvider().newSHA256Digest(), new XMSSSigner(), 32);
        }
    }

    static public class withShake128andPrehash
            extends XMSSSignatureSpi {
        public withShake128andPrehash() {
            super("SHAKE128withXMSSMT-SHAKE128", HashingProviderProvider.getHashingProvider().newSHAKE128Digest(), new XMSSSigner(), 64);
        }
    }

    static public class withSha512andPrehash
            extends XMSSSignatureSpi {
        public withSha512andPrehash() {
            super("SHA512withXMSS-SHA512", HashingProviderProvider.getHashingProvider().newSHA512Digest(), new XMSSSigner(), 64);
        }
    }

    static public class withShake256andPrehash
            extends XMSSSignatureSpi {
        public withShake256andPrehash() {
            super("SHAKE256withXMSS-SHAKE256", HashingProviderProvider.getHashingProvider().newSHAKE256Digest(), new XMSSSigner(), 128);
        }
    }

    static public class withSha2_192andPrehash
            extends XMSSSignatureSpi {
        public withSha2_192andPrehash() {
            super("SHA2_192withXMSS-SHA2_192", HashingProviderProvider.getHashingProvider().newSHA256Digest(), new XMSSSigner(), 24);
        }
    }

    static public class withShake256_256andPrehash
            extends XMSSSignatureSpi {
        public withShake256_256andPrehash() {
            super("SHAKE256_256withXMSS-SHAKE256_256", HashingProviderProvider.getHashingProvider().newSHAKE256Digest(), new XMSSSigner(), 32);
        }
    }

    static public class withShake256_192andPrehash
            extends XMSSSignatureSpi {
        public withShake256_192andPrehash() {
            super("SHAKE256_192withXMSS-SHAKE256_192", HashingProviderProvider.getHashingProvider().newSHAKE256Digest(), new XMSSSigner(), 24);
        }
    }

}
