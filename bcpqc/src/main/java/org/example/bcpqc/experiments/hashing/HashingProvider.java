package org.example.bcpqc.experiments.hashing;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.example.bcpqc.pqc.crypto.lms.hash.LMSHash;
import org.example.bcpqc.pqc.crypto.sphincsplus.SPHINCSPlusEngines;
import org.example.bcpqc.pqc.crypto.xmss.khf.KeyedHashFunctions;

public interface HashingProvider {
    KeyedHashFunctions newKHF(ASN1ObjectIdentifier treeDigest, int digestSize);

    LMSHash newLMSHash(ASN1ObjectIdentifier treeDigest, int digestSize);

    SPHINCSPlusEngines getSphincsPlusEngines();

    Digest newSHA256Digest();

    Digest newSHA512Digest();

    Digest newSHAKE128Digest();

    Digest newSHAKE256Digest();

    default Digest getDigest(ASN1ObjectIdentifier oid) {
        if (oid.equals(NISTObjectIdentifiers.id_sha256)) {
            return newSHA256Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha512)) {
            return newSHA512Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake128)) {
            return newSHAKE128Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake256)) {
            return newSHAKE256Digest();
        }
        throw new IllegalArgumentException("unrecognized digest OID: " + oid);
    }
}
