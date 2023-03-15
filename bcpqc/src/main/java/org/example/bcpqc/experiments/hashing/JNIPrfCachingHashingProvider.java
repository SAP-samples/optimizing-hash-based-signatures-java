package org.example.bcpqc.experiments.hashing;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.example.bcpqc.pqc.crypto.lms.hash.LMSHash;
import org.example.bcpqc.pqc.crypto.sphincsplus.SPHINCSPlusEngines;
import org.example.bcpqc.pqc.crypto.xmss.khf.JniSHA2PrfCachingKHF;
import org.example.bcpqc.pqc.crypto.xmss.khf.KeyedHashFunctions;
import org.example.jnihash.JniSha256Digest;

public class JNIPrfCachingHashingProvider implements HashingProvider {
    private final ThreadLocal<JniSHA2PrfCachingKHF> jniSHA2PrfCachingKHFThreadLocal = ThreadLocal.withInitial(() -> new JniSHA2PrfCachingKHF(32));

    private final ThreadLocal<JniSha256Digest> jniSha256DigestThreadLocal = ThreadLocal.withInitial(JniSha256Digest::new);

    @Override
    public KeyedHashFunctions newKHF(ASN1ObjectIdentifier treeDigest, int digestSize) {
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha256) && digestSize == 32) {
            return jniSHA2PrfCachingKHFThreadLocal.get();
        }
        throw new IllegalArgumentException("Unknown digest");

    }

    @Override
    public SPHINCSPlusEngines getSphincsPlusEngines() {
        return null;
    }

    @Override
    public LMSHash newLMSHash(ASN1ObjectIdentifier treeDigest, int digestSize) {
        throw new RuntimeException("LMS not supported");
    }

    @Override
    public Digest newSHA256Digest() {
        return jniSha256DigestThreadLocal.get();
    }

    @Override
    public Digest newSHA512Digest() {
        return null;
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