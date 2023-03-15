package org.example.bcpqc.experiments.hashing;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.example.bcpqc.pqc.crypto.lms.hash.JniSha2LmsHash;
import org.example.bcpqc.pqc.crypto.lms.hash.JniShake256LmsHash;
import org.example.bcpqc.pqc.crypto.lms.hash.LMSHash;
import org.example.bcpqc.pqc.crypto.sphincsplus.JNISphincsPlusEngines;
import org.example.bcpqc.pqc.crypto.sphincsplus.SPHINCSPlusEngines;
import org.example.bcpqc.pqc.crypto.xmss.khf.JniSHA2KHF;
import org.example.bcpqc.pqc.crypto.xmss.khf.JniSHAKE256KHF;
import org.example.bcpqc.pqc.crypto.xmss.khf.KeyedHashFunctions;
import org.example.jnihash.JniSha256Digest;
import org.example.jnihash.JniShake256Digest;

public class JNIHashingProvider implements HashingProvider {
    private final ThreadLocal<JniSHA2KHF> jniSHA2_32KHFThreadLocal = ThreadLocal.withInitial(() -> new JniSHA2KHF(32));
    private final ThreadLocal<JniSHA2KHF> jniSHA2_24KHFThreadLocal = ThreadLocal.withInitial(() -> new JniSHA2KHF(24));
    private final ThreadLocal<JniSHAKE256KHF> jniSHAKE256_32KHFThreadLocal = ThreadLocal.withInitial(() -> new JniSHAKE256KHF(32));
    private final ThreadLocal<JniSHAKE256KHF> jniSHAKE256_24KHFThreadLocal = ThreadLocal.withInitial(() -> new JniSHAKE256KHF(24));
    private final ThreadLocal<JniSha2LmsHash> jniSha2LmsHash24ThreadLocal = ThreadLocal.withInitial(() -> new JniSha2LmsHash(24));
    private final ThreadLocal<JniSha2LmsHash> jniSha2LmsHash32ThreadLocal = ThreadLocal.withInitial(() -> new JniSha2LmsHash(32));
    private final ThreadLocal<JniShake256LmsHash> jniShake256LmsHash24ThreadLocal = ThreadLocal.withInitial(() -> new JniShake256LmsHash(24));
    private final ThreadLocal<JniShake256LmsHash> jniShake256LmsHash32ThreadLocal = ThreadLocal.withInitial(() -> new JniShake256LmsHash(32));

    private final ThreadLocal<JniSha256Digest> jniSha256DigestThreadLocal = ThreadLocal.withInitial(JniSha256Digest::new);
    private final ThreadLocal<JniShake256Digest> jniShake256DigestThreadLocal = ThreadLocal.withInitial(JniShake256Digest::new);

    @Override
    public KeyedHashFunctions newKHF(ASN1ObjectIdentifier treeDigest, int digestSize) {
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha256)) {
            if (digestSize == 32) {
                return jniSHA2_32KHFThreadLocal.get();
            } else if (digestSize == 24) {
                return jniSHA2_24KHFThreadLocal.get();
            }
        } else if (treeDigest.equals(NISTObjectIdentifiers.id_shake256)) {
            if (digestSize == 32) {
                return jniSHAKE256_32KHFThreadLocal.get();
            } else if (digestSize == 24) {
                return jniSHAKE256_24KHFThreadLocal.get();
            }
        }
        throw new IllegalArgumentException("Unknown digest");
    }

    @Override
    public SPHINCSPlusEngines getSphincsPlusEngines() {
        return JNISphincsPlusEngines.INSTANCE;
    }

    @Override
    public Digest getDigest(ASN1ObjectIdentifier oid) {
        return HashingProvider.super.getDigest(oid);
    }

    @Override
    public LMSHash newLMSHash(ASN1ObjectIdentifier treeDigest, int digestSize) {
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha256)) {
            if (digestSize == 32) {
                return jniSha2LmsHash32ThreadLocal.get();
            } else if (digestSize == 24) {
                return jniSha2LmsHash24ThreadLocal.get();
            }
        } else if (treeDigest.equals(NISTObjectIdentifiers.id_shake256)) {
            if (digestSize == 32) {
                return jniShake256LmsHash32ThreadLocal.get();
            } else if (digestSize == 24) {
                return jniShake256LmsHash24ThreadLocal.get();
            }
        }
        throw new IllegalArgumentException("Unknown digest");
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
        return jniShake256DigestThreadLocal.get();
    }
}
