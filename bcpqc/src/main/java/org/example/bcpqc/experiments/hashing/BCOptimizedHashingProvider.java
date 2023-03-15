package org.example.bcpqc.experiments.hashing;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.example.bcpqc.crypto.digests.SHA256Digest;
import org.example.bcpqc.pqc.crypto.lms.hash.BcOptimizedSha256LmsHash;
import org.example.bcpqc.pqc.crypto.lms.hash.LMSHash;
import org.example.bcpqc.pqc.crypto.sphincsplus.SPHINCSPlusEngines;
import org.example.bcpqc.pqc.crypto.xmss.khf.BcSha256OptimizedKHF;
import org.example.bcpqc.pqc.crypto.xmss.khf.KeyedHashFunctions;

public class BCOptimizedHashingProvider implements HashingProvider {

    public KeyedHashFunctions newKHF(ASN1ObjectIdentifier treeDigest, int digestSize) {
        if(!treeDigest.equals(NISTObjectIdentifiers.id_sha256)){
            throw new IllegalArgumentException("Unsupported digest");
        }
        return new BcSha256OptimizedKHF(digestSize);
    }

    public Digest newSHA256Digest() {
        return new SHA256Digest();
    }

    public Digest newSHA512Digest() {
        return null;
    }

    public Digest newSHAKE128Digest() {
        return null;
    }

    public Digest newSHAKE256Digest() {
        return null;
    }

    @Override
    public LMSHash newLMSHash(ASN1ObjectIdentifier treeDigest, int digestSize) {
        if (!treeDigest.equals(NISTObjectIdentifiers.id_sha256)) {
            throw new IllegalArgumentException("Unsupported digest");
        }
        return new BcOptimizedSha256LmsHash(digestSize);

    }

    @Override
    public SPHINCSPlusEngines getSphincsPlusEngines() {
        return null;
    }
}
