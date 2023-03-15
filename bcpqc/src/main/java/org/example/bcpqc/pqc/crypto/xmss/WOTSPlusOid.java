package org.example.bcpqc.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * WOTS+ OID class.
 */
final class WOTSPlusOid
        implements XMSSOid {

    /**
     * XMSS OID lookup table.
     */
    private static final Map<String, WOTSPlusOid> oidLookupTable;

    static {
        Map<String, WOTSPlusOid> map = new HashMap<String, WOTSPlusOid>();
        map.put(createKey("SHA-256", 32, 16, 67), new WOTSPlusOid(0x01000001, "WOTSP_SHA2-256_W16"));
        map.put(createKey("SHA-512", 64, 16, 131), new WOTSPlusOid(0x02000002, "WOTSP_SHA2-512_W16"));
        map.put(createKey("SHAKE128", 32, 16, 67), new WOTSPlusOid(0x03000003, "WOTSP_SHAKE128_W16"));
        map.put(createKey("SHAKE256", 64, 16, 131), new WOTSPlusOid(0x04000004, "WOTSP_SHAKE256_W16"));
        // We use oids deviating from the NIST SP/RFC analogous to oids already definied in BC. I don't know why they
        // use different oids, but I want to make sure that there are no collisions with XMSS oids.
        map.put(createKey("SHA-256", 24, 16, 51), new WOTSPlusOid(0x05000005, "WOTSP_SHA2-192_W16"));
        map.put(createKey("SHAKE256", 32, 16, 67), new WOTSPlusOid(0x06000006, "WOTSP_SHAKE256_256_W16"));
        map.put(createKey("SHAKE256", 24, 16, 51), new WOTSPlusOid(0x06000006, "WOTSP_SHAKE256_192_W16"));

        oidLookupTable = Collections.unmodifiableMap(map);
    }

    /**
     * OID.
     */
    private final int oid;
    /**
     * String representation of OID.
     */
    private final String stringRepresentation;

    /**
     * Constructor...
     *
     * @param oid                  OID.
     * @param stringRepresentation String representation of OID.
     */
    private WOTSPlusOid(int oid, String stringRepresentation) {
        super();
        this.oid = oid;
        this.stringRepresentation = stringRepresentation;
    }

    /**
     * Lookup OID.
     *
     * @param algorithmName       Algorithm name.
     * @param winternitzParameter Winternitz parameter.
     * @return WOTS+ OID if parameters were found, null else.
     */
    protected static WOTSPlusOid lookup(String algorithmName, int digestSize, int winternitzParameter, int len) {
        if (algorithmName == null) {
            throw new NullPointerException("algorithmName == null");
        }
        return oidLookupTable.get(createKey(algorithmName, digestSize, winternitzParameter, len));
    }

    /**
     * Create a key based on parameters.
     *
     * @param algorithmName       Algorithm name.
     * @param winternitzParameter Winternitz Parameter.
     * @return String representation of parameters for lookup table.
     */
    private static String createKey(String algorithmName, int digestSize, int winternitzParameter, int len) {
        if (algorithmName == null) {
            throw new NullPointerException("algorithmName == null");
        }
        return algorithmName + "-" + digestSize + "-" + winternitzParameter + "-" + len;
    }

    /**
     * Getter OID.
     *
     * @return OID.
     */
    public int getOid() {
        return oid;
    }

    public String toString() {
        return stringRepresentation;
    }
}
