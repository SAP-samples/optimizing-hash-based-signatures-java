package org.example.bcpqc.pqc.crypto.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

public class DigestUtil {
    private static Map<String, ASN1ObjectIdentifier> nameToOid = new HashMap<String, ASN1ObjectIdentifier>();
    private static Map<ASN1ObjectIdentifier, String> oidToName = new HashMap<ASN1ObjectIdentifier, String>();

    static {
        nameToOid.put("SHA-256", NISTObjectIdentifiers.id_sha256);
        nameToOid.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        nameToOid.put("SHAKE128", NISTObjectIdentifiers.id_shake128);
        nameToOid.put("SHAKE256", NISTObjectIdentifiers.id_shake256);

        oidToName.put(NISTObjectIdentifiers.id_sha256, "SHA-256");
        oidToName.put(NISTObjectIdentifiers.id_sha512, "SHA-512");
        oidToName.put(NISTObjectIdentifiers.id_shake128, "SHAKE128");
        oidToName.put(NISTObjectIdentifiers.id_shake256, "SHAKE256");
    }

    public static String getDigestName(ASN1ObjectIdentifier oid) {
        String name = oidToName.get(oid);
        if (name != null) {
            return name;
        }

        throw new IllegalArgumentException("unrecognized digest oid: " + oid);
    }

    public static ASN1ObjectIdentifier getDigestOID(String name) {
        ASN1ObjectIdentifier oid = nameToOid.get(name);
        if (oid != null) {
            return oid;
        }

        throw new IllegalArgumentException("unrecognized digest name: " + name);
    }

    public static int getPaddingSize(int digestSize) {
        switch (digestSize) {
            case 32:
                return 32;
            case 24:
                return 4;
            case 64:
                return 64;
            default:
                throw new IllegalArgumentException("Invalid digest size: " + digestSize);
        }
    }
}
