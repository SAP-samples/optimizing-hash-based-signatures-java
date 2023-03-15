package org.example.bcpqc.experiments.hashing;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.example.bcpqc.pqc.crypto.lms.hash.LMSHash;
import org.example.bcpqc.pqc.crypto.lms.hash.MessageDigestLmsHash;
import org.example.bcpqc.pqc.crypto.sphincsplus.SPHINCSPlusEngines;
import org.example.bcpqc.pqc.crypto.xmss.DigestMessageDigestAdapter;
import org.example.bcpqc.pqc.crypto.xmss.khf.KeyedHashFunctions;
import org.example.bcpqc.pqc.crypto.xmss.khf.MessageDigestKHF;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class CorrettoHashingProvider implements HashingProvider {
    static {
        if (Security.getProvider(AmazonCorrettoCryptoProvider.PROVIDER_NAME) == null) {
            Security.addProvider(AmazonCorrettoCryptoProvider.INSTANCE);

            AmazonCorrettoCryptoProvider.INSTANCE.assertHealthy();
        }
    }

    @Override
    public KeyedHashFunctions newKHF(ASN1ObjectIdentifier treeDigest, int digestSize) {
        MessageDigest messageDigest = getMessageDigest(treeDigest);
        return new MessageDigestKHF(messageDigest, digestSize);
    }

    @Override
    public LMSHash newLMSHash(ASN1ObjectIdentifier treeDigest, int digestSize) {
        MessageDigest messageDigest = getMessageDigest(treeDigest);
        return new MessageDigestLmsHash(messageDigest, digestSize);
    }

    @Override
    public SPHINCSPlusEngines getSphincsPlusEngines() {
        return null;
    }

    @Override
    public Digest newSHA256Digest() {
        return DigestMessageDigestAdapter.correttoSha256();
    }

    @Override
    public Digest newSHA512Digest() {
        return DigestMessageDigestAdapter.correttoSha512();
    }

    @Override
    public Digest newSHAKE128Digest() {
        return null;
    }

    @Override
    public Digest newSHAKE256Digest() {
        return null;
    }

    private MessageDigest getMessageDigest(ASN1ObjectIdentifier oid) {
        MessageDigest messageDigest = null;
        try {
            if (oid.equals(NISTObjectIdentifiers.id_sha256)) {
                messageDigest = MessageDigest.getInstance("SHA-256", AmazonCorrettoCryptoProvider.PROVIDER_NAME);
            }
            if (oid.equals(NISTObjectIdentifiers.id_sha512)) {
                messageDigest = MessageDigest.getInstance("SHA-512", AmazonCorrettoCryptoProvider.PROVIDER_NAME);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        if (messageDigest == null) {
            throw new IllegalArgumentException("Unsupported digest");
        }
        return messageDigest;
    }
}
