package org.example.bcpqc.pqc.crypto.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class WOTSPlusCParameters extends WOTSPlusParameters {

    // Constant sum of all blocks
    private final int s;
    // Number of leading zero blocks
    private final int z;

    public WOTSPlusCParameters(ASN1ObjectIdentifier treeDigest, int digestSize, int s, int z, int winternitzParameter) {
        super(treeDigest, digestSize, winternitzParameter);

        if (winternitzParameter != 4 && winternitzParameter != 16) {
            throw new IllegalArgumentException("Unsupported Winternitz parameter");
        }

        this.s = s;
        this.z = z;
    }

    public int getS() {
        return s;
    }

    public int getZ() {
        return z;
    }

    @Override
    protected int getLen() {
        return getLen1();
    }

    @Override
    protected int getLen1() {
        return super.getLen1() - z;
    }

    @Override
    protected int getLen2() {
        return 0;
    }
}
