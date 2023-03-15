package org.example.bcpqc.asn1.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;

public interface SAPBCObjectIdentifiers extends BCObjectIdentifiers {
    public static final ASN1ObjectIdentifier xmss_SHA2_192 = xmss.branch("9");
    public static final ASN1ObjectIdentifier xmss_SHAKE256_256 = xmss.branch("10");
    public static final ASN1ObjectIdentifier xmss_SHAKE256_192 = xmss.branch("11");
    public static final ASN1ObjectIdentifier xmss_SHA2_192ph = xmss.branch("12");
    public static final ASN1ObjectIdentifier xmss_SHAKE256_256ph = xmss.branch("13");
    public static final ASN1ObjectIdentifier xmss_SHAKE256_192ph = xmss.branch("14");


    public static final ASN1ObjectIdentifier xmss_mt_SHA2_192 = xmss_mt.branch("9");
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE256_256 = xmss_mt.branch("10");
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE256_192 = xmss_mt.branch("11");
    public static final ASN1ObjectIdentifier xmss_mt_SHA2_192ph = xmss_mt.branch("12");
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE256_256ph = xmss_mt.branch("13");
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE256_192ph = xmss_mt.branch("14");

    /**
     * SPHINCS+
     * <p>
     * COpied here because it is not present in BCObjectIndentifiers in BC 1.70
     */
    public static final ASN1ObjectIdentifier sphincsPlus = bc_sig.branch("5");
    public static final ASN1ObjectIdentifier sphincsPlus_shake_256 = sphincsPlus.branch("1");
    public static final ASN1ObjectIdentifier sphincsPlus_sha_256 = sphincsPlus.branch("2");
    public static final ASN1ObjectIdentifier sphincsPlus_sha_512 = sphincsPlus.branch("3");
    public static final ASN1ObjectIdentifier sphincsPlus_haraka = sphincsPlus.branch("4");
}
