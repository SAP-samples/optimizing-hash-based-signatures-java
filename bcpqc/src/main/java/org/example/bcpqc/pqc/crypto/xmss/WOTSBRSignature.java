package org.example.bcpqc.pqc.crypto.xmss;

public class WOTSBRSignature extends WOTSPlusSignature {
    private final long ctr;
    private final int maxSum;

    WOTSBRSignature(WOTSPlusParameters params, byte[][] signature, long ctr, int maxSum) {
        super(params, signature);
        this.ctr = ctr;
        this.maxSum = maxSum;
    }

    public long getCtr() {
        return ctr;
    }

    public int getMaxSum() {
        return maxSum;
    }

}
