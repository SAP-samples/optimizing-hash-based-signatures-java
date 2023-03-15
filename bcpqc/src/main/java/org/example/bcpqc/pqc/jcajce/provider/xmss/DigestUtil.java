package org.example.bcpqc.pqc.jcajce.provider.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.NullDigest;
import org.example.bcpqc.pqc.jcajce.spec.XMSSParameterSpec;

class DigestUtil {

    static ASN1ObjectIdentifier getDigestOID(String digest) {
        if (digest.equals("SHA-256")) {
            return NISTObjectIdentifiers.id_sha256;
        }
        if (digest.equals("SHA-512")) {
            return NISTObjectIdentifiers.id_sha512;
        }
        if (digest.equals("SHAKE128")) {
            return NISTObjectIdentifiers.id_shake128;
        }
        if (digest.equals("SHAKE256")) {
            return NISTObjectIdentifiers.id_shake256;
        }

        throw new IllegalArgumentException("unrecognized digest: " + digest);
    }

    public static byte[] getDigestResult(Digest digest, int digestSize) {
        // Handle NullDigest
        if (digest instanceof NullDigest) {
            byte[] hash = new byte[digest.getDigestSize()];
            digest.doFinal(hash, 0);
            return hash;
        }

        byte[] hash = new byte[digestSize];

        if (digest instanceof Xof) {
            ((Xof) digest).doFinal(hash, 0, hash.length);
        } else if (digestSize < digest.getDigestSize()) {
            // Handle SHA-256/192
            byte[] buffer = new byte[digest.getDigestSize()];
            digest.doFinal(buffer, 0);
            System.arraycopy(buffer, 0, hash, 0, digestSize);
        } else {
            digest.doFinal(hash, 0);
        }

        return hash;
    }

    public static String getXMSSDigestName(ASN1ObjectIdentifier treeDigest) {
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha256)) {
            return XMSSParameterSpec.SHA256;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha512)) {
            return XMSSParameterSpec.SHA512;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_shake128)) {
            return XMSSParameterSpec.SHAKE128;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_shake256)) {
            return XMSSParameterSpec.SHAKE256;
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + treeDigest);
    }
}
