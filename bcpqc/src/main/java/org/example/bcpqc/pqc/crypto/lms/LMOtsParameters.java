package org.example.bcpqc.pqc.crypto.lms;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

public class LMOtsParameters {
    /*
     * The following Python script can be used to calculate the parameters :
     *
     * # Calculates the LMS-OTS parameters according to RFC 8554, Appendix B
     * import math
     * def u(n, w):
     *     return math.ceil(8*n/w)
     * def v(n, w):
     *     return math.ceil((math.floor(math.log(((2 ** w) - 1) * u(n,w), 2)) + 1) / w)
     * def ls(n, w):
     *     return 16 - (v(n,w) * w)
     * def p(n, w):
     *     return u(n, w) + v(n, w)
     *
     * n = int(input("n = "))
     * w = int(input("w = "))
     *
     * print()
     * print("u = " + str(u(n, w)))
     * print("v = " + str(v(n, w)))
     * print("ls = " + str(ls(n, w)))
     * print("p = " + str(p(n,w)))
     * print("size = " + str((p(n, w) + 1) * n + 4))
     *
     */
    public static final int reserved = 0;
    public static final LMOtsParameters sha256_n32_w1 = new LMOtsParameters(1, 32, 1, 265, 7, 8516, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w2 = new LMOtsParameters(2, 32, 2, 133, 6, 4292, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w4 = new LMOtsParameters(3, 32, 4, 67, 4, 2180, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w8 = new LMOtsParameters(4, 32, 8, 34, 0, 1124, NISTObjectIdentifiers.id_sha256);

    public static final LMOtsParameters sha256_n24_w1 = new LMOtsParameters(5, 24, 1, 200, 8, 4828, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n24_w2 = new LMOtsParameters(6, 24, 2, 101, 6, 2452, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n24_w4 = new LMOtsParameters(7, 24, 4, 51, 4, 1252, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n24_w8 = new LMOtsParameters(8, 24, 8, 26, 0, 652, NISTObjectIdentifiers.id_sha256);

    public static final LMOtsParameters shake_n32_w1 = new LMOtsParameters(9, 32, 1, 265, 7, 8516, NISTObjectIdentifiers.id_shake256);
    public static final LMOtsParameters shake_n32_w2 = new LMOtsParameters(0xA, 32, 2, 133, 6, 4292, NISTObjectIdentifiers.id_shake256);
    public static final LMOtsParameters shake_n32_w4 = new LMOtsParameters(0xB, 32, 4, 67, 4, 2180, NISTObjectIdentifiers.id_shake256);
    public static final LMOtsParameters shake_n32_w8 = new LMOtsParameters(0xC, 32, 8, 34, 0, 1124, NISTObjectIdentifiers.id_shake256);

    public static final LMOtsParameters shake_n24_w1 = new LMOtsParameters(0xD, 24, 1, 100, 8, 4828, NISTObjectIdentifiers.id_shake256);
    public static final LMOtsParameters shake_n24_w2 = new LMOtsParameters(0xE, 24, 2, 101, 6, 2452, NISTObjectIdentifiers.id_shake256);
    public static final LMOtsParameters shake_n24_w4 = new LMOtsParameters(0xF, 24, 4, 51, 4, 1252, NISTObjectIdentifiers.id_shake256);
    public static final LMOtsParameters shake_n24_w8 = new LMOtsParameters(0x10, 24, 8, 26, 0, 652, NISTObjectIdentifiers.id_shake256);

    private static final Map<Object, LMOtsParameters> suppliers = new HashMap<Object, LMOtsParameters>() {
        {
            put(sha256_n32_w1.type, sha256_n32_w1);
            put(sha256_n32_w2.type, sha256_n32_w2);
            put(sha256_n32_w4.type, sha256_n32_w4);
            put(sha256_n32_w8.type, sha256_n32_w8);

            put(sha256_n24_w1.type, sha256_n24_w1);
            put(sha256_n24_w2.type, sha256_n24_w2);
            put(sha256_n24_w4.type, sha256_n24_w4);
            put(sha256_n24_w8.type, sha256_n24_w8);

            put(shake_n32_w1.type, shake_n32_w1);
            put(shake_n32_w2.type, shake_n32_w2);
            put(shake_n32_w4.type, shake_n32_w4);
            put(shake_n32_w8.type, shake_n32_w8);

            put(shake_n24_w1.type, shake_n24_w1);
            put(shake_n24_w2.type, shake_n24_w2);
            put(shake_n24_w4.type, shake_n24_w4);
            put(shake_n24_w8.type, shake_n24_w8);

        }
    };

    private final int type;
    private final int n;
    private final int w;
    private final int p;
    private final int ls;
    private final int sigLen;
    private final ASN1ObjectIdentifier digestOID;

    protected LMOtsParameters(int type, int n, int w, int p, int ls, int sigLen, ASN1ObjectIdentifier digestOID) {
        this.type = type;
        this.n = n;
        this.w = w;
        this.p = p;
        this.ls = ls;
        this.sigLen = sigLen;
        this.digestOID = digestOID;
    }

    public static LMOtsParameters getParametersForType(int type) {
        return suppliers.get(type);
    }

    public int getType() {
        return type;
    }

    public int getN() {
        return n;
    }

    public int getW() {
        return w;
    }

    public int getP() {
        return p;
    }

    public int getLs() {
        return ls;
    }

    public int getSigLen() {
        return sigLen;
    }

    public ASN1ObjectIdentifier getDigestOID() {
        return digestOID;
    }
}
