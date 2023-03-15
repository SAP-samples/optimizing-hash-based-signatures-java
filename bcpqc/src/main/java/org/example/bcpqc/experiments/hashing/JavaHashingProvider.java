package org.example.bcpqc.experiments.hashing;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.example.bcpqc.pqc.crypto.lms.hash.LMSHash;
import org.example.bcpqc.pqc.crypto.lms.hash.MessageDigestLmsHash;
import org.example.bcpqc.pqc.crypto.sphincsplus.JavaSphincsPlusEngines;
import org.example.bcpqc.pqc.crypto.sphincsplus.SPHINCSPlusEngines;
import org.example.bcpqc.pqc.crypto.xmss.DigestMessageDigestAdapter;
import org.example.bcpqc.pqc.crypto.xmss.khf.KeyedHashFunctions;
import org.example.bcpqc.pqc.crypto.xmss.khf.MessageDigestKHF;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class JavaHashingProvider implements HashingProvider {
    @Override
    public KeyedHashFunctions newKHF(ASN1ObjectIdentifier treeDigest, int digestSize) {
        return new MessageDigestKHF(getMessageDigest(treeDigest), digestSize);
    }

    @Override
    public LMSHash newLMSHash(ASN1ObjectIdentifier treeDigest, int digestSize) {
        MessageDigest messageDigest = getMessageDigest(treeDigest);
        return new MessageDigestLmsHash(messageDigest, digestSize);
    }

    @Override
    public SPHINCSPlusEngines getSphincsPlusEngines() {
        return JavaSphincsPlusEngines.INSTANCE;
    }

    @Override
    public Digest newSHA256Digest() {
        return DigestMessageDigestAdapter.sunSha256();
    }

    @Override
    public Digest newSHA512Digest() {
        return DigestMessageDigestAdapter.sunSha512();
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
                messageDigest = MessageDigest.getInstance("SHA-256", "SUN");
            }
            if (oid.equals(NISTObjectIdentifiers.id_sha512)) {
                messageDigest = MessageDigest.getInstance("SHA-512", "SUN");
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
