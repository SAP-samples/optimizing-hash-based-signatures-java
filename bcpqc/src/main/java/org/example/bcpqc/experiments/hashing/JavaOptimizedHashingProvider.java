package org.example.bcpqc.experiments.hashing;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.example.bcpqc.pqc.crypto.lms.hash.JavaOptimizedSha256LmsHash;
import org.example.bcpqc.pqc.crypto.lms.hash.LMSHash;
import org.example.bcpqc.pqc.crypto.sphincsplus.SPHINCSPlusEngines;
import org.example.bcpqc.pqc.crypto.xmss.DigestMessageDigestAdapter;
import org.example.bcpqc.pqc.crypto.xmss.khf.JavaOptimizedSHA2KHF;
import org.example.bcpqc.pqc.crypto.xmss.khf.KeyedHashFunctions;

public class JavaOptimizedHashingProvider implements HashingProvider {
    @Override
    public KeyedHashFunctions newKHF(ASN1ObjectIdentifier treeDigest, int digestSize) {
        if (!treeDigest.equals(NISTObjectIdentifiers.id_sha256)) {
            throw new IllegalArgumentException("Unsupported digest");
        }

        return new JavaOptimizedSHA2KHF(digestSize);
    }

    @Override
    public LMSHash newLMSHash(ASN1ObjectIdentifier treeDigest, int digestSize) {
        if (!treeDigest.equals(NISTObjectIdentifiers.id_sha256)) {
            throw new IllegalArgumentException("Unsupported digest");
        }

        return new JavaOptimizedSha256LmsHash(digestSize);
    }

    @Override
    public SPHINCSPlusEngines getSphincsPlusEngines() {
        return null;
    }

    @Override
    public Digest newSHA256Digest() {
        return DigestMessageDigestAdapter.sunSha256();
    }

    @Override
    public Digest newSHA512Digest() {
        return DigestMessageDigestAdapter.sunSha256();
    }

    @Override
    public Digest newSHAKE128Digest() {
        return null;
    }

    @Override
    public Digest newSHAKE256Digest() {
        return null;
    }

}
