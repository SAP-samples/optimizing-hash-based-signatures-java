package org.example.bcpqc.experiments.hashing;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.example.bcpqc.pqc.crypto.lms.hash.JniFixedPaddingSha2LmsHash;
import org.example.bcpqc.pqc.crypto.lms.hash.LMSHash;
import org.example.bcpqc.pqc.crypto.sphincsplus.SPHINCSPlusEngines;
import org.example.bcpqc.pqc.crypto.xmss.khf.JniSHA2FixedPaddingKHF;
import org.example.bcpqc.pqc.crypto.xmss.khf.KeyedHashFunctions;
import org.example.jnihash.JniSha256Digest;

public class JNIFixedPaddingHashingProvider implements HashingProvider {

    private final ThreadLocal<JniSHA2FixedPaddingKHF> jniSHA2_32FixedPaddingKHFThreadLocal = ThreadLocal.withInitial(() -> new JniSHA2FixedPaddingKHF(32));
    private final ThreadLocal<JniSHA2FixedPaddingKHF> jniSHA2_24FixedPaddingKHFThreadLocal = ThreadLocal.withInitial(() -> new JniSHA2FixedPaddingKHF(24));
    private final ThreadLocal<JniFixedPaddingSha2LmsHash> jniFixedPaddingSha2_32LmsHashThreadLocal = ThreadLocal.withInitial(() -> new JniFixedPaddingSha2LmsHash(32));
    private final ThreadLocal<JniFixedPaddingSha2LmsHash> jniFixedPaddingSha2_24LmsHashThreadLocal = ThreadLocal.withInitial(() -> new JniFixedPaddingSha2LmsHash(24));

    private final ThreadLocal<JniSha256Digest> jniSha256DigestThreadLocal = ThreadLocal.withInitial(JniSha256Digest::new);

    @Override
    public KeyedHashFunctions newKHF(ASN1ObjectIdentifier treeDigest, int digestSize) {
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha256)) {
            if (digestSize == 32) {
                return jniSHA2_32FixedPaddingKHFThreadLocal.get();
            } else if (digestSize == 24) {
                return jniSHA2_24FixedPaddingKHFThreadLocal.get();
            }
        }
        throw new IllegalArgumentException("Unknown digest");

    }

    @Override
    public LMSHash newLMSHash(ASN1ObjectIdentifier treeDigest, int digestSize) {
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha256)) {
            if (digestSize == 32) {
                return this.jniFixedPaddingSha2_32LmsHashThreadLocal.get();
            } else if (digestSize == 24) {
                return this.jniFixedPaddingSha2_24LmsHashThreadLocal.get();
            }
        }
        throw new IllegalArgumentException("Unknown digest");

    }

    @Override
    public SPHINCSPlusEngines getSphincsPlusEngines() {
        return null;
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
