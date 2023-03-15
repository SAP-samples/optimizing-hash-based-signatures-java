package org.example.bcpqc.pqc.jcajce.provider.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;
import org.example.bcpqc.experiments.hashing.HashingProvider;
import org.example.bcpqc.experiments.hashing.HashingProviderProvider;
import org.example.bcpqc.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.example.bcpqc.pqc.crypto.xmss.XMSSMTSigner;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class XMSSMTSignatureSpi
        extends Signature
        implements StateAwareSignature {
    protected XMSSMTSignatureSpi(String algorithm) {
        super(algorithm);
    }

    private Digest digest;
    private XMSSMTSigner signer;
    private ASN1ObjectIdentifier treeDigest;
    private SecureRandom random;
    private int digestSize;

    protected XMSSMTSignatureSpi(String sigName, Digest digest, XMSSMTSigner signer, int digestSize) {
        super(sigName);

        this.digest = digest;
        this.signer = signer;
        this.digestSize = digestSize;
    }

    protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException {
        if (publicKey instanceof BCXMSSMTPublicKey) {
            CipherParameters param = ((BCXMSSMTPublicKey) publicKey).getKeyParams();

            treeDigest = null;
            digest.reset();
            signer.init(false, param);
        } else {
            throw new InvalidKeyException("unknown public key passed to XMSSMT");
        }
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException {
        this.random = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException {
        if (privateKey instanceof BCXMSSMTPrivateKey) {
            CipherParameters param = ((BCXMSSMTPrivateKey) privateKey).getKeyParams();

            treeDigest = ((BCXMSSMTPrivateKey) privateKey).getTreeDigestOID();
            if (random != null) {
                param = new ParametersWithRandom(param, random);
            }

            digest.reset();
            signer.init(true, param);
        } else {
            throw new InvalidKeyException("unknown private key passed to XMSSMT");
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
            throw new SignatureException(e.toString());
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
        PrivateKey rKey = new BCXMSSMTPrivateKey(treeDigest, (XMSSMTPrivateKeyParameters) signer.getUpdatedPrivateKey());

        treeDigest = null;

        return rKey;
    }

    static public class generic
            extends XMSSMTSignatureSpi {
        public generic() {
            super("XMSSMT", new NullDigest(), new XMSSMTSigner(), -1);
        }
    }

    static public class withSha256
            extends XMSSMTSignatureSpi {
        public withSha256() {
            super("XMSSMT-SHA256", new NullDigest(), new XMSSMTSigner(), -1);
        }
    }

    static public class withShake128
            extends XMSSMTSignatureSpi {
        public withShake128() {
            super("XMSSMT-SHAKE128", new NullDigest(), new XMSSMTSigner(), -1);
        }
    }

    static public class withSha512
            extends XMSSMTSignatureSpi {
        public withSha512() {
            super("XMSSMT-SHA512", new NullDigest(), new XMSSMTSigner(), -1);
        }
    }

    static public class withShake256
            extends XMSSMTSignatureSpi {
        public withShake256() {
            super("XMSSMT-SHAKE256", new NullDigest(), new XMSSMTSigner(), -1);
        }
    }

    static public class withSha2_192
            extends XMSSMTSignatureSpi {
        public withSha2_192() {
            super("XMSSMT-SHA2_192", new NullDigest(), new XMSSMTSigner(), -1);
        }
    }

    static public class withShake256_256
            extends XMSSMTSignatureSpi {
        public withShake256_256() {
            super("XMSSMT-SHAKE256_256", new NullDigest(), new XMSSMTSigner(), -1);
        }
    }

    static public class withShake256_192
            extends XMSSMTSignatureSpi {
        public withShake256_192() {
            super("XMSSMT-SHAKE256_192", new NullDigest(), new XMSSMTSigner(), -1);
        }
    }


    static public class withSha256andPrehash
            extends XMSSMTSignatureSpi {
        public withSha256andPrehash() {
            super("SHA256withXMSSMT-SHA256", HashingProviderProvider.getHashingProvider().newSHA256Digest(), new XMSSMTSigner(), 32);
        }
    }

    static public class withShake128andPrehash
            extends XMSSMTSignatureSpi {
        public withShake128andPrehash() {
            super("SHAKE128withXMSSMT-SHAKE128", HashingProviderProvider.getHashingProvider().newSHAKE128Digest(), new XMSSMTSigner(), 32);
        }
    }

    static public class withSha512andPrehash
            extends XMSSMTSignatureSpi {
        public withSha512andPrehash() {
            super("SHA512withXMSSMT-SHA512", HashingProviderProvider.getHashingProvider().newSHA512Digest(), new XMSSMTSigner(), 64);
        }
    }

    static public class withShake256andPrehash
            extends XMSSMTSignatureSpi {
        public withShake256andPrehash() {
            super("SHAKE256withXMSSMT-SHAKE256", HashingProviderProvider.getHashingProvider().newSHAKE256Digest(), new XMSSMTSigner(), 64);
        }
    }

    static public class withSha2_192andPrehash
            extends XMSSMTSignatureSpi {
        public withSha2_192andPrehash() {
            super("SHA2_192withXMSSMT-SHA2_192", HashingProviderProvider.getHashingProvider().newSHA256Digest(), new XMSSMTSigner(), 24);
        }
    }

    static public class withShake256_256andPrehash
            extends XMSSMTSignatureSpi {
        public withShake256_256andPrehash() {
            super("SHAKE256_256withXMSSMT-SHAKE256_256", HashingProviderProvider.getHashingProvider().newSHAKE256Digest(), new XMSSMTSigner(), 32);
        }
    }

    static public class withShake256_192andPrehash
            extends XMSSMTSignatureSpi {
        public withShake256_192andPrehash() {
            super("SHAKE256_192withXMSSMT-SHAKE256_192", HashingProviderProvider.getHashingProvider().newSHAKE256Digest(), new XMSSMTSigner(), 24);
        }
    }

}
