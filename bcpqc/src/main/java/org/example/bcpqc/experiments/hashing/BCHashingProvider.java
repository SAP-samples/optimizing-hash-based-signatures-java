package org.example.bcpqc.experiments.hashing;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.example.bcpqc.crypto.digests.SHA256Digest;
import org.example.bcpqc.pqc.crypto.lms.hash.BcDigestLmsHash;
import org.example.bcpqc.pqc.crypto.lms.hash.LMSHash;
import org.example.bcpqc.pqc.crypto.sphincsplus.BCSphincsPlusEngines;
import org.example.bcpqc.pqc.crypto.sphincsplus.SPHINCSPlusEngines;
import org.example.bcpqc.pqc.crypto.xmss.khf.BCDigestKHF;
import org.example.bcpqc.pqc.crypto.xmss.khf.KeyedHashFunctions;

public class BCHashingProvider implements HashingProvider {
    public KeyedHashFunctions newKHF(ASN1ObjectIdentifier treeDigest, int digestSize) {
        Digest digest = getDigest(treeDigest);
        return new BCDigestKHF(digest, digestSize);
    }

    public Digest newSHA256Digest() {
        return new SHA256Digest();
    }

    public Digest newSHA512Digest() {
        return new SHA512Digest();
    }

    public Digest newSHAKE128Digest() {
        return new SHAKEDigest(128);
    }

    public Digest newSHAKE256Digest() {
        return new SHAKEDigest(256);
    }

    @Override
    public LMSHash newLMSHash(ASN1ObjectIdentifier treeDigest, int digestSize) {
        Digest digest = getDigest(treeDigest);
        return new BcDigestLmsHash(digest, digestSize);
    }

    @Override
    public SPHINCSPlusEngines getSphincsPlusEngines() {
        return BCSphincsPlusEngines.INSTANCE;
    }
}
