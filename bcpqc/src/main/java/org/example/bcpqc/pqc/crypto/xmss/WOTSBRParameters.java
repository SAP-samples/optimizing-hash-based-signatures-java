package org.example.bcpqc.pqc.crypto.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class WOTSBRParameters extends WOTSPlusParameters {
    private final boolean useOnePadding;
    private final int iterationsR;

    private final boolean includeChecksum;
    private final int checksumRequiredBits;
    private final int checksumAllocatedBits;
    private final int checksumUnusedBits;

    public WOTSBRParameters(ASN1ObjectIdentifier treeDigest, int digestSize, boolean useOnePadding, int iterationsR, boolean includeChecksum, int winternitzParameter) {
        super(treeDigest, digestSize, winternitzParameter);

        if (winternitzParameter != 4 && winternitzParameter != 16) {
            throw new IllegalArgumentException("Unsupported Winternitz parameter");
        }

        this.useOnePadding = useOnePadding;
        this.iterationsR = iterationsR;
        this.includeChecksum = includeChecksum;

        this.checksumRequiredBits = (int) Math.ceil(Math.log(getLen1() * (getWinternitzParameter() - 1)) / Math.log(2));
        this.checksumAllocatedBits = getLen2() * getLogW();
        this.checksumUnusedBits = this.checksumAllocatedBits - this.checksumRequiredBits;

    }

    public int getChecksumRequiredBits() {
        return checksumRequiredBits;
    }

    public int getChecksumAllocatedBits() {
        return checksumAllocatedBits;
    }

    public int getChecksumUnusedBits() {
        return checksumUnusedBits;
    }

    public int getIterationsR() {
        return iterationsR;
    }

    public boolean isUseOnePadding() {
        return useOnePadding;
    }

    public boolean isIncludeChecksum() {
        return includeChecksum;
    }
}
